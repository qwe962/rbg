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

package rbg

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/rbgs/api/workloads/constants"
	workloadsv1alpha2 "sigs.k8s.io/rbgs/api/workloads/v1alpha2"
	"sigs.k8s.io/rbgs/test/envtest/testutil"
	"sigs.k8s.io/yaml"
)

// The layout from #627: the decode role's base template has metadata only and its
// container comes from leaderTemplatePatch. It is created as unstructured, as kubectl
// would, because the typed struct cannot leave a template spec out.
const scaledSiblingOfTemplateWithoutSpec = `
apiVersion: workloads.x-k8s.io/v1alpha2
kind: RoleBasedGroup
metadata:
  name: pd
spec:
  roles:
  - name: prefill
    replicas: 1
    scalingAdapter:
      enable: true
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

var _ = Describe("ScalingAdapter next to a role template without spec", func() {
	const timeout = 30 * time.Second
	const interval = 200 * time.Millisecond
	var namespace string

	BeforeEach(func() {
		namespace = fmt.Sprintf("adapter-template-without-spec-%d", time.Now().UnixNano())
		testutil.CreateNamespace(namespace)
	})
	AfterEach(func() { testutil.DeleteNamespace(namespace) })

	// The adapter used to Update the whole RoleBasedGroup, which re-sent the decode
	// template as "spec: {containers: null}"; the API server rejected it with
	// "spec.roles[1].leaderWorkerPattern.template.spec.containers: Required value" and
	// the prefill replicas were never written.
	It("scales the sibling role and leaves the template without spec untouched", func() {
		obj := &unstructured.Unstructured{}
		Expect(yaml.Unmarshal([]byte(scaledSiblingOfTemplateWithoutSpec), &obj.Object)).To(Succeed())
		obj.SetNamespace(namespace)
		Expect(testutil.K8sClient.Create(testutil.Ctx, obj)).To(Succeed())
		key := client.ObjectKey{Namespace: namespace, Name: "pd"}

		adapterKey := client.ObjectKey{Namespace: namespace, Name: workloadsv1alpha2.GenerateScalingAdapterName("pd", "prefill")}
		Eventually(func() (constants.AdapterPhase, error) {
			adapter := &workloadsv1alpha2.RoleBasedGroupScalingAdapter{}
			err := testutil.K8sClient.Get(testutil.Ctx, adapterKey, adapter)
			return adapter.Status.Phase, err
		}, timeout, interval).Should(Equal(constants.AdapterPhaseBound))

		Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &workloadsv1alpha2.RoleBasedGroupScalingAdapter{}
			if err := testutil.K8sClient.Get(testutil.Ctx, adapterKey, current); err != nil {
				return err
			}
			body := &autoscalingv1.Scale{
				ObjectMeta: metav1.ObjectMeta{Name: current.Name, Namespace: namespace, ResourceVersion: current.ResourceVersion},
				Spec:       autoscalingv1.ScaleSpec{Replicas: 2},
			}
			return testutil.K8sClient.SubResource("scale").Update(testutil.Ctx, current, client.WithSubResourceBody(body))
		})).To(Succeed())

		Eventually(func() (int32, error) {
			rbg := &workloadsv1alpha2.RoleBasedGroup{}
			if err := testutil.K8sClient.Get(testutil.Ctx, key, rbg); err != nil {
				return 0, err
			}
			return *rbg.Spec.Roles[0].Replicas, nil
		}, timeout, interval).Should(Equal(int32(2)), "the adapter did not write the prefill replicas")

		stored := &unstructured.Unstructured{}
		stored.SetGroupVersionKind(workloadsv1alpha2.GroupVersion.WithKind("RoleBasedGroup"))
		Expect(testutil.K8sClient.Get(testutil.Ctx, key, stored)).To(Succeed())
		roles, _, err := unstructured.NestedSlice(stored.Object, "spec", "roles")
		Expect(err).NotTo(HaveOccurred())
		template, _, err := unstructured.NestedMap(roles[1].(map[string]any), "leaderWorkerPattern", "template")
		Expect(err).NotTo(HaveOccurred())
		Expect(template).NotTo(HaveKey("spec"))
	})
})
