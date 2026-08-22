/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2/ktesting"
)

const (
	testSecretName      = "istio-csr-serving-cert"
	testSecretNamespace = "cert-manager"
	testTrustDomain     = "cluster.local"
)

func TestProvider_loadFromSecret(t *testing.T) {
	caPEM, caCert, caPK := genTestCA(t)
	servingCertPEM, servingKeyPEM, servingNotAfter := genServingCert(t, caCert, caPK)
	_, otherKeyPEM, _ := genServingCert(t, caCert, caPK)

	// A CA that signed nothing in this test. Used to prove that a serving
	// certificate which does not chain to the effective mesh roots is rejected.
	unrelatedCAPEM, _, _ := genTestCA(t)

	expiredCertPEM, expiredKeyPEM, _ := genServingCertValidFor(t, caCert, caPK,
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	futureCertPEM, futureKeyPEM, _ := genServingCertValidFor(t, caCert, caPK,
		time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))

	tests := map[string]struct {
		secret *corev1.Secret
		// rootCAsCertFile being set means the CA came from disk, so ca.crt in the
		// Secret must not be required.
		rootCAsCertFile string
		preloadRootCAs  []byte
		expErr          bool
		expErrContains  string
		expNotAfter     time.Time
	}{
		"a Secret with tls.crt, tls.key and ca.crt loads successfully": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"tls.key": servingKeyPEM,
				"ca.crt":  caPEM,
			}),
			expNotAfter: servingNotAfter,
		},
		"a missing Secret returns an error naming the Secret": {
			secret:         nil,
			expErr:         true,
			expErrContains: "failed to get serving certificate Secret",
		},
		"a Secret without tls.crt returns an error": {
			secret: newSecret(map[string][]byte{
				"tls.key": servingKeyPEM,
				"ca.crt":  caPEM,
			}),
			expErr:         true,
			expErrContains: "missing tls.crt",
		},
		"a Secret without tls.key returns an error": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"ca.crt":  caPEM,
			}),
			expErr:         true,
			expErrContains: "missing tls.key",
		},
		"a Secret without ca.crt returns an error when no RootCAsCertFile is set": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"tls.key": servingKeyPEM,
			}),
			expErr: true,
		},
		"a Secret without ca.crt succeeds when RootCAsCertFile is set": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"tls.key": servingKeyPEM,
			}),
			rootCAsCertFile: "/etc/ca/root.pem",
			// The roots come from disk rather than the Secret, but they must still
			// be the roots that signed the serving certificate.
			preloadRootCAs: caPEM,
			expNotAfter:    servingNotAfter,
		},
		"a serving certificate that does not chain to the mesh roots is rejected": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"tls.key": servingKeyPEM,
			}),
			rootCAsCertFile: "/etc/ca/root.pem",
			preloadRootCAs:  unrelatedCAPEM,
			expErr:          true,
			expErrContains:  "against the current mesh roots",
		},
		"a Secret whose tls.key does not match tls.crt returns an error": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"tls.key": otherKeyPEM,
				"ca.crt":  caPEM,
			}),
			expErr:         true,
			expErrContains: "failed to parse serving certificate from Secret",
		},
		"an expired certificate is rejected rather than scheduling a negative renewal": {
			secret: newSecret(map[string][]byte{
				"tls.crt": expiredCertPEM,
				"tls.key": expiredKeyPEM,
				"ca.crt":  caPEM,
			}),
			expErr:         true,
			expErrContains: "is not currently valid",
		},
		"a not-yet-valid certificate is rejected": {
			secret: newSecret(map[string][]byte{
				"tls.crt": futureCertPEM,
				"tls.key": futureKeyPEM,
				"ca.crt":  caPEM,
			}),
			expErr:         true,
			expErrContains: "is not currently valid",
		},
		"a malformed ca.crt is rejected before it can be published": {
			secret: newSecret(map[string][]byte{
				"tls.crt": servingCertPEM,
				"tls.key": servingKeyPEM,
				"ca.crt":  []byte("not a CA bundle"),
			}),
			expErr:         true,
			expErrContains: "failed to decode ca.crt",
		},
		"a Secret with a malformed tls.crt returns an error": {
			secret: newSecret(map[string][]byte{
				"tls.crt": []byte("not a certificate"),
				"tls.key": servingKeyPEM,
				"ca.crt":  caPEM,
			}),
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			logger, _ := ktesting.NewTestContext(t)

			var objects []runtime.Object
			if test.secret != nil {
				objects = append(objects, test.secret)
			}
			client := k8sfake.NewSimpleClientset(objects...)

			p := &Provider{
				log:       logger,
				k8sClient: client,
				opts: Options{
					TrustDomain:                       testTrustDomain,
					RootCAsCertFile:                   test.rootCAsCertFile,
					ServingCertificateSecretName:      testSecretName,
					ServingCertificateSecretNamespace: testSecretNamespace,
				},
			}

			// When the CA comes from disk rather than the Secret, the Provider
			// already holds it by the time loadFromSecret runs.
			if len(test.preloadRootCAs) > 0 {
				require.NoError(t, p.loadCAsRoot(test.preloadRootCAs))
			}

			notAfter, err := p.loadFromSecret(context.Background())

			if test.expErr {
				require.Error(t, err)
				if test.expErrContains != "" {
					require.ErrorContains(t, err, test.expErrContains)
				}
				return
			}

			require.NoError(t, err)
			require.WithinDuration(t, test.expNotAfter, notAfter, time.Second,
				"returned NotAfter should be the leaf certificate's NotAfter")

			// The resulting tls.Config must be usable for serving.
			require.NotNil(t, p.tlsConfig)
			require.Len(t, p.tlsConfig.Certificates, 1)
			require.Equal(t, uint16(0x0303), p.tlsConfig.MinVersion, "expected TLS 1.2 minimum")
			require.Equal(t, []string{"h2"}, p.tlsConfig.NextProtos)
			require.NotNil(t, p.tlsConfig.ClientCAs)
			require.NotNil(t, p.tlsConfig.VerifyPeerCertificate)
		})
	}
}

func newSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSecretName,
			Namespace: testSecretNamespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: data,
	}
}

// genTestCA returns a self-signed CA suitable for signing serving certificates.
func genTestCA(t *testing.T) ([]byte, *x509.Certificate, crypto.Signer) {
	t.Helper()

	pk, err := pki.GenerateECPrivateKey(256)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey:             pk.Public(),
		IsCA:                  true,
	}

	caPEM, caCert, err := pki.SignCertificate(tmpl, tmpl, pk.Public(), pk)
	require.NoError(t, err)

	return caPEM, caCert, pk
}

// genServingCert returns a leaf certificate signed by the given CA, its private
// key, and the leaf's NotAfter.
func genServingCert(t *testing.T, caCert *x509.Certificate, caPK crypto.Signer) ([]byte, []byte, time.Time) {
	t.Helper()
	return genServingCertValidFor(t, caCert, caPK, time.Now().Add(-time.Minute), time.Now().Add(30*time.Minute))
}

// genServingCertValidFor is genServingCert with an explicit validity window, for
// exercising the not-currently-valid rejection.
func genServingCertValidFor(t *testing.T, caCert *x509.Certificate, caPK crypto.Signer, notBefore, notAfter time.Time) ([]byte, []byte, time.Time) {
	t.Helper()

	pk, err := pki.GenerateECPrivateKey(256)
	require.NoError(t, err)

	notAfter = notAfter.Truncate(time.Second)
	tmpl := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "istio-csr.cert-manager.svc"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PublicKey:             pk.Public(),
		DNSNames:              []string{"istio-csr.cert-manager.svc"},
	}

	certPEM, _, err := pki.SignCertificate(tmpl, caCert, pk.Public(), caPK)
	require.NoError(t, err)

	keyPEM, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	require.NoError(t, err)

	return certPEM, keyPEM, notAfter
}

// A failed refresh must not leave a new trust bundle published while the old
// serving certificate is still in use. loadCAsRoot both swaps p.rootCAs and
// notifies subscribers, so it must run only after everything else has parsed.
func TestProvider_loadFromSecret_failedRefreshDoesNotPublishCA(t *testing.T) {
	logger, _ := ktesting.NewTestContext(t)

	caPEM, caCert, caPK := genTestCA(t)
	certPEM, keyPEM, _ := genServingCert(t, caCert, caPK)

	// A second, unrelated CA that a rotated Secret might carry.
	newCAPEM, _, _ := genTestCA(t)
	require.NotEqual(t, caPEM, newCAPEM)

	good := newSecret(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": caPEM})
	client := k8sfake.NewSimpleClientset(good)

	p := &Provider{
		log:       logger,
		k8sClient: client,
		opts: Options{
			TrustDomain:                       testTrustDomain,
			ServingCertificateSecretName:      testSecretName,
			ServingCertificateSecretNamespace: testSecretNamespace,
		},
	}

	// First load succeeds and publishes the original CA.
	_, err := p.loadFromSecret(context.Background())
	require.NoError(t, err)
	require.Equal(t, caPEM, p.rootCAs.PEM, "first load should publish the Secret's CA")
	servingBefore := p.tlsConfig

	// The Secret now carries a NEW ca.crt but a key that does not match the cert.
	_, mismatchedKeyPEM, _ := genServingCert(t, caCert, caPK)
	broken := newSecret(map[string][]byte{
		"tls.crt": certPEM,
		"tls.key": mismatchedKeyPEM,
		"ca.crt":  newCAPEM,
	})
	_, err = client.CoreV1().Secrets(testSecretNamespace).Update(
		context.Background(), broken, metav1.UpdateOptions{})
	require.NoError(t, err)

	_, err = p.loadFromSecret(context.Background())
	require.Error(t, err, "a mismatched key pair must fail the refresh")

	require.Equal(t, caPEM, p.rootCAs.PEM,
		"the failed refresh must NOT publish the new CA while the old certificate is still served")
	require.Same(t, servingBefore, p.tlsConfig,
		"the serving certificate must be left untouched by a failed refresh")
}

// A Secret can carry a new ca.crt alongside a tls.crt that does not chain to it
// -- a partially-written or hand-edited Secret, or the wrong CA pasted in. Every
// cheap check passes: the key pair matches, the leaf parses, it is inside its
// validity window, and ca.crt decodes. Only the chain verification catches it.
//
// That makes the ORDER of the chain verification load-bearing rather than
// incidental. loadCAsRoot fans the new bundle out to subscribers, and the
// ConfigMap controller rewrites istio-ca-root-cert in every namespace in the
// mesh in response. Verifying after publishing would point every workload at a
// CA that does not match the certificate istio-csr is still serving.
func TestProvider_loadFromSecret_unchainedCARotationIsNotPublished(t *testing.T) {
	logger, _ := ktesting.NewTestContext(t)

	caPEM, caCert, caPK := genTestCA(t)
	certPEM, keyPEM, _ := genServingCert(t, caCert, caPK)

	newCAPEM, _, _ := genTestCA(t)
	require.NotEqual(t, caPEM, newCAPEM)

	good := newSecret(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": caPEM})
	client := k8sfake.NewSimpleClientset(good)

	p := &Provider{
		log:       logger,
		k8sClient: client,
		opts: Options{
			TrustDomain:                       testTrustDomain,
			ServingCertificateSecretName:      testSecretName,
			ServingCertificateSecretNamespace: testSecretNamespace,
		},
	}

	_, err := p.loadFromSecret(context.Background())
	require.NoError(t, err)
	require.Equal(t, caPEM, p.rootCAs.PEM)
	servingBefore := p.tlsConfig

	// Subscribe the way the ConfigMap controller does, so we can assert that a
	// mesh-wide trust bundle update is never announced.
	events := p.SubscribeRootCAsEvent()

	// New ca.crt, but the SAME still-valid key pair, which was signed by the old
	// CA. Everything before the chain verification succeeds.
	rotated := newSecret(map[string][]byte{
		"tls.crt": certPEM,
		"tls.key": keyPEM,
		"ca.crt":  newCAPEM,
	})
	_, err = client.CoreV1().Secrets(testSecretNamespace).Update(
		context.Background(), rotated, metav1.UpdateOptions{})
	require.NoError(t, err)

	_, err = p.loadFromSecret(context.Background())
	require.Error(t, err, "a serving certificate that does not chain to the Secret's ca.crt must fail")
	require.Contains(t, err.Error(), "against the current mesh roots")

	require.Equal(t, caPEM, p.rootCAs.PEM,
		"the unchained CA must NOT be published to the mesh trust bundle")
	require.Same(t, servingBefore, p.tlsConfig,
		"the serving certificate must be left untouched")

	select {
	case <-events:
		t.Fatal("a root CA change was broadcast to subscribers; the ConfigMap controller " +
			"would have rewritten istio-ca-root-cert in every namespace")
	case <-time.After(100 * time.Millisecond):
	}
}
