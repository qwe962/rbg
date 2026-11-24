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

package metricsauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"
)

const (
	controllerSA = "rbgs-controller-sa"
	readerSA     = "metrics-reader"
	strangerSA   = "metrics-stranger"
)

// reviewResources are the resources the metrics filter creates as the controller.
var reviewResources = map[string]string{
	"authentication.k8s.io": "tokenreviews",
	"authorization.k8s.io":  "subjectaccessreviews",
}

var _ = Describe("Secure metrics endpoint", func() {
	var ns string

	BeforeEach(func() {
		created, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "metrics-auth-"},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		ns = created.Name
		for _, sa := range []string{controllerSA, readerSA, strangerSA} {
			_, err := clientset.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: sa},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		bindClusterRole(ns, readerSA, rbacv1.ClusterRole{Rules: []rbacv1.PolicyRule{{
			NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"},
		}}})
	})

	It("returns 200 to an authorized scraper and 403 to an unauthorized one with the generated ClusterRole", func() {
		bindClusterRole(ns, controllerSA, generatedControllerRole())
		addr := startMetricsServer(ns)

		Eventually(func() int { return scrape(addr, token(ns, readerSA)) }).
			WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).
			Should(Equal(http.StatusOK))
		Expect(scrape(addr, token(ns, strangerSA))).To(Equal(http.StatusForbidden))
	})

	// Shows the endpoint fails when the controller lacks the review grants, so the
	// spec above depends on config/rbac/role.yaml carrying them (#640).
	It("returns 500 when the controller ClusterRole lacks the review grants", func() {
		role := generatedControllerRole()
		role.Rules = slices.DeleteFunc(role.Rules, func(rule rbacv1.PolicyRule) bool {
			return slices.ContainsFunc(rule.APIGroups, func(g string) bool { return reviewResources[g] != "" })
		})
		bindClusterRole(ns, controllerSA, role)
		waitForControllerRBAC(ns)
		addr := startMetricsServer(ns)

		Eventually(func() int { return scrape(addr, token(ns, readerSA)) }).
			WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).
			Should(Equal(http.StatusInternalServerError))
	})
})

// generatedControllerRole returns the rules controller-gen renders from the
// kubebuilder RBAC markers; the Helm chart and deploy/kubectl are generated from it.
func generatedControllerRole() rbacv1.ClusterRole {
	_, thisFile, _, ok := runtime.Caller(0)
	Expect(ok).To(BeTrue())
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "config", "rbac", "role.yaml")
	raw, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	var role rbacv1.ClusterRole
	Expect(yaml.UnmarshalStrict(raw, &role)).To(Succeed())
	return role
}

func bindClusterRole(ns, sa string, role rbacv1.ClusterRole) {
	name := fmt.Sprintf("%s-%s", ns, sa)
	role.ObjectMeta = metav1.ObjectMeta{Name: name}
	_, err := clientset.RbacV1().ClusterRoles().Create(ctx, &role, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: sa, Namespace: ns}},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() {
		_ = clientset.RbacV1().ClusterRoleBindings().Delete(context.Background(), name, metav1.DeleteOptions{})
		_ = clientset.RbacV1().ClusterRoles().Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

// controllerConfig acts as the controller ServiceAccount, the identity the metrics
// filter uses for its TokenReviews and SubjectAccessReviews in a real deployment.
func controllerConfig(ns string) *rest.Config {
	c := rest.CopyConfig(cfg)
	c.Impersonate = rest.ImpersonationConfig{
		UserName: fmt.Sprintf("system:serviceaccount:%s:%s", ns, controllerSA),
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
	}
	return c
}

// waitForControllerRBAC waits until the controller binding is in effect, so a 500
// cannot come from RBAC that has not propagated yet.
func waitForControllerRBAC(ns string) {
	cs, err := kubernetes.NewForConfig(controllerConfig(ns))
	Expect(err).NotTo(HaveOccurred())
	Eventually(func() bool {
		review, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "list", Resource: "pods"},
			},
		}, metav1.CreateOptions{})
		return err == nil && review.Status.Allowed
	}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(BeTrue())
}

func startMetricsServer(ns string) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	addr := l.Addr().String()
	Expect(l.Close()).To(Succeed())

	c := controllerConfig(ns)
	httpClient, err := rest.HTTPClientFor(c)
	Expect(err).NotTo(HaveOccurred())
	srv, err := metricsserver.NewServer(metricsserver.Options{
		BindAddress:    addr,
		SecureServing:  true,
		FilterProvider: filters.WithAuthenticationAndAuthorization,
	}, c, httpClient)
	Expect(err).NotTo(HaveOccurred())

	srvCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.Start(srvCtx) }()
	DeferCleanup(func() {
		stop()
		Eventually(done).WithTimeout(10 * time.Second).Should(Receive(BeNil()))
	})
	return addr
}

func token(ns, sa string) string {
	tr, err := clientset.CoreV1().ServiceAccounts(ns).CreateToken(ctx, sa, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: ptr.To[int64](600)},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return tr.Status.Token
}

// scrape returns the HTTP status of GET /metrics, or 0 while the server is not up.
func scrape(addr, bearer string) int {
	client := &http.Client{
		Timeout: 5 * time.Second,
		// The metrics server generates a self-signed certificate.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
