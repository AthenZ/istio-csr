# Copyright 2023 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

repo_name := github.com/cert-manager/istio-csr

kind_cluster_name := istio-csr
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

build_names := manager

go_manager_main_dir := ./cmd
go_manager_mod_dir := .
go_manager_ldflags := -X $(repo_name)/internal/version.AppVersion=$(VERSION) -X $(repo_name)/internal/version.GitCommit=$(GITCOMMIT)
oci_manager_base_image_flavor := static
# Image and chart are SEPARATE Docker Hub repositories sharing a version tag.
# Docker Hub has no nested repositories, so the chart cannot live under a
# "charts/" path and must be flat in the namespace -- which means it would
# collide with the image if both used the same name. The siblings solve this the
# same way: athenz-cert-manager-issuer (image) vs athenz-issuer (chart),
# athenz-csi-driver (image) vs csi-driver-athenz (chart).
oci_manager_image_name := docker.io/athenz/athenz-istio-csr
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := athenz.local/athenz-istio-csr
oci_platforms := linux/amd64,linux/arm64

deploy_name := istio-csr
deploy_namespace := cert-manager

helm_chart_source_dir := deploy/charts/istio-csr
# No "charts/" segment: Docker Hub does not support nested repositories, and
# helm.mk derives the push destination as $(dir $(helm_chart_image_name)). This
# publishes the chart flat at docker.io/athenz/cert-manager-istio-csr, which is
# where the kdnc and fleks addons pull from via
# oci://docker.ouroath.com:4443/docker.io/athenz.
# $(notdir ...) must equal Chart.yaml's name; helm.mk asserts it.
helm_chart_image_name := docker.io/athenz/cert-manager-istio-csr
helm_chart_version := $(VERSION)
helm_labels_template_name := cert-manager-istio-csr.labels

golangci_lint_config := .golangci.yaml

# docker.io/athenz/cert-manager-istio-csr -> "docker.io" and "athenz".
# Derived rather than hardcoded so they cannot drift from oci_manager_image_name.
oci_manager_image_registry := $(firstword $(subst /, ,$(oci_manager_image_name)))
oci_manager_image_namespace := $(word 2,$(subst /, ,$(oci_manager_image_name)))
# -> athenz-istio-csr. The chart defaults image.name to cert-manager-istio-csr,
# which is the CHART's repository, so it must be overridden too.
oci_manager_image_repository := $(word 3,$(subst /, ,$(oci_manager_image_name)))

# Point the packaged chart at the fork's registry. Upstream ships
# imageRegistry/imageNamespace defaulting to quay.io/jetstack, and this chart has
# no mutation function, so without this a released chart would still pull the
# upstream image.
#
# imageRegistry/imageNamespace are mutated rather than image.repository so the
# chart keeps its upstream shape: image.repository stays empty and consumers can
# still use either mechanism. The tag is left alone -- the image helper falls back
# to .Chart.AppVersion, which is set to the release version at package time.
define helm_values_mutation_function
$(YQ) \
	'( .imageRegistry = "$(oci_manager_image_registry)" ) | \
	( .imageNamespace = "$(oci_manager_image_namespace)" ) | \
	( .image.name = "$(oci_manager_image_repository)" )' \
	$1 --inplace
endef

images_amd64 ?=
images_arm64 ?=

images_amd64 += docker.io/kong/httpbin:0.1.0@sha256:9d65a5b1955d2466762f53ea50eebae76be9dc7e277217cd8fb9a24b004154f4
images_arm64 += docker.io/kong/httpbin:0.1.0@sha256:c546c8b06c542b615f053b577707cb72ddc875a0731d56d0ffaf840f767322ad

images_amd64 += quay.io/curl/curl:8.5.0@sha256:e40a76dcfa9405678336774130411ca35beba85db426d5755b3cdd7b99d09a7a
images_arm64 += quay.io/curl/curl:8.5.0@sha256:038b0290c9e4a371aed4f9d6993e3548fcfa32b96e9a170bfc73f5da4ec2354d
