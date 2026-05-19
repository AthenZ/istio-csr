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

package options

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cert-manager/istio-csr/pkg/tls"
)

func Test_validateServingCertificateOptions(t *testing.T) {
	tests := map[string]struct {
		opts           tls.Options
		expErr         bool
		expErrContains string
	}{
		"DNS names alone are valid (the default CertificateRequest path)": {
			opts: tls.Options{
				ServingCertificateDNSNames: []string{"cert-manager-istio-csr.cert-manager.svc"},
			},
		},
		"no DNS names and no Secret is rejected": {
			opts:           tls.Options{},
			expErr:         true,
			expErrContains: "the list of DNS names to add to the serving certificate is empty",
		},
		"a Secret name and namespace alone are valid, DNS names not required": {
			opts: tls.Options{
				ServingCertificateSecretName:      "istio-csr-serving-cert",
				ServingCertificateSecretNamespace: "cert-manager",
			},
		},
		"a Secret name without a namespace is rejected": {
			opts: tls.Options{
				ServingCertificateSecretName: "istio-csr-serving-cert",
			},
			expErr:         true,
			expErrContains: "--serving-certificate-secret-namespace must be set",
		},
		"a namespace without a Secret name still requires DNS names": {
			opts: tls.Options{
				ServingCertificateSecretNamespace: "cert-manager",
			},
			expErr:         true,
			expErrContains: "the list of DNS names to add to the serving certificate is empty",
		},
		"DNS names and a fully specified Secret together are valid": {
			opts: tls.Options{
				ServingCertificateDNSNames:        []string{"cert-manager-istio-csr.cert-manager.svc"},
				ServingCertificateSecretName:      "istio-csr-serving-cert",
				ServingCertificateSecretNamespace: "cert-manager",
			},
		},
		"DNS names with a Secret name but no namespace is still rejected": {
			opts: tls.Options{
				ServingCertificateDNSNames:   []string{"cert-manager-istio-csr.cert-manager.svc"},
				ServingCertificateSecretName: "istio-csr-serving-cert",
			},
			expErr:         true,
			expErrContains: "--serving-certificate-secret-namespace must be set",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateServingCertificateOptions(test.opts)

			if test.expErr {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expErrContains)
				return
			}

			require.NoError(t, err)
		})
	}
}
