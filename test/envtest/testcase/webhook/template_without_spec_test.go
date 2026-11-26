/*
Copyright 2026 The RBG Authors.

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

package webhook

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	workloadsv1alpha2 "sigs.k8s.io/rbgs/api/workloads/v1alpha2"
	"sigs.k8s.io/rbgs/test/envtest/testutil"
	"sigs.k8s.io/yaml"
)

// templateWithoutSpecRBG is the layout from #627: the decode role's base template
// has metadata only and its container comes from leaderTemplatePatch. The prefill
// role carries the legacy "Recreate" type so the defaulter has something to heal.
const templateWithoutSpecRBG = `
apiVersion: workloads.x-k8s.io/v1alpha2
kind: RoleBasedGroup
metadata:
  name: pd
spec:
  roles:
  - name: prefill
    replicas: 1
    rolloutStrategy:
      rollingUpdate:
        type: Recreate
    leaderWorkerPattern:
      size: 1
      template:
        spec:
          containers:
          - name: sglang
            image: registry.k8s.io/pause:3.10
  - name: decode
    replicas: 1
    leaderWorkerPattern:
      size: 1
      template:
        metadata:
          labels:
            app: pd
      leaderTemplatePatch:
        spec:
          containers:
          - name: sglang
            image: registry.k8s.io/pause:3.10
`

var _ = Describe("Mutating webhook on a role template without spec", func() {
	var testNs string

	BeforeEach(func() {
		testNs = fmt.Sprintf("test-template-without-spec-%d", time.Now().UnixNano())
		testutil.CreateNamespace(testNs)
	})

	AfterEach(func() {
		testutil.DeleteNamespace(testNs)
	})

	// The CustomDefaulter handler diffed the request against the whole re-encoded
	// typed object, which added "spec: {containers: null}" to the decode template, so
	// the API server rejected the create and every later write (#627).
	It("admits create and later writes, heals the legacy type and adds no template spec", func() {
		obj := &unstructured.Unstructured{}
		Expect(yaml.Unmarshal([]byte(templateWithoutSpecRBG), &obj.Object)).To(Succeed())
		obj.SetNamespace(testNs)
		Expect(testutil.K8sClient.Create(testutil.Ctx, obj)).To(Succeed())
		key := types.NamespacedName{Namespace: testNs, Name: "pd"}

		expectStored := func(replicas int64) {
			stored := &unstructured.Unstructured{}
			stored.SetGroupVersionKind(workloadsv1alpha2.GroupVersion.WithKind("RoleBasedGroup"))
			Expect(testutil.K8sClient.Get(testutil.Ctx, key, stored)).To(Succeed())
			roles, _, err := unstructured.NestedSlice(stored.Object, "spec", "roles")
			Expect(err).NotTo(HaveOccurred())
			prefill, decode := roles[0].(map[string]any), roles[1].(map[string]any)

			strategy, _, err := unstructured.NestedString(prefill, "rolloutStrategy", "rollingUpdate", "type")
			Expect(err).NotTo(HaveOccurred())
			Expect(strategy).To(Equal(string(workloadsv1alpha2.RecreatePodUpdateStrategyType)),
				"the defaulter must still heal Recreate")
			storedReplicas, _, err := unstructured.NestedInt64(prefill, "replicas")
			Expect(err).NotTo(HaveOccurred())
			Expect(storedReplicas).To(Equal(replicas))
			template, _, err := unstructured.NestedMap(decode, "leaderWorkerPattern", "template")
			Expect(err).NotTo(HaveOccurred())
			Expect(template).NotTo(HaveKey("spec"), "admission must not add a spec to the decode template")
		}
		expectStored(1)

		// The ScalingAdapter's write: only the prefill replicas.
		patch := []byte(`[{"op":"test","path":"/spec/roles/0/name","value":"prefill"},` +
			`{"op":"add","path":"/spec/roles/0/replicas","value":2}]`)
		rbg := &workloadsv1alpha2.RoleBasedGroup{}
		Expect(testutil.K8sClient.Get(testutil.Ctx, key, rbg)).To(Succeed())
		Expect(testutil.K8sClient.Patch(testutil.Ctx, rbg, client.RawPatch(types.JSONPatchType, patch))).To(Succeed())
		expectStored(2)

		// A user edit that touches neither role template.
		Expect(testutil.K8sClient.Patch(testutil.Ctx, rbg, client.RawPatch(types.MergePatchType,
			[]byte(`{"metadata":{"labels":{"edited":"true"}}}`)))).To(Succeed())
		expectStored(2)
	})
})
