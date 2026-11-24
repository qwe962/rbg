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

package chart

import (
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// metricsAuthGrants are the API calls the secure metrics endpoint makes as the
// controller: filters.WithAuthenticationAndAuthorization verifies a scraper's
// bearer token with a TokenReview and checks "get /metrics" with a
// SubjectAccessReview. Without them every scrape fails with HTTP 500.
var metricsAuthGrants = []struct{ group, resource string }{
	{"authentication.k8s.io", "tokenreviews"},
	{"authorization.k8s.io", "subjectaccessreviews"},
}

func controllerClusterRole(t *testing.T, manifest string) rbacv1.ClusterRole {
	t.Helper()
	obj, ok := splitObjects(t, manifest)["ClusterRole/"+controllerClusterRoleName]
	if !ok {
		t.Fatalf("ClusterRole %q not found in rendered chart", controllerClusterRoleName)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal([]byte(obj.raw), &role); err != nil {
		t.Fatalf("unmarshal ClusterRole: %v", err)
	}
	return role
}

func allowsCreate(role rbacv1.ClusterRole, group, resource string) bool {
	for _, rule := range role.Rules {
		if slices.Contains(rule.APIGroups, group) && slices.Contains(rule.Resources, resource) &&
			(slices.Contains(rule.Verbs, "create") || slices.Contains(rule.Verbs, rbacv1.VerbAll)) {
			return true
		}
	}
	return false
}

// TestClusterRoleGrantsMetricsAuthReviews guards #640: the chart serves metrics over
// HTTPS with authn/authz by default, so the controller ClusterRole must let the
// controller create TokenReviews and SubjectAccessReviews whatever the
// deprecated-workload-types toggle says.
func TestClusterRoleGrantsMetricsAuthReviews(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
	}{
		{"default", renderChart(t)},
		{"enabled", renderEnabled(t)},
		{"disabled", renderDisabled(t)},
	} {
		role := controllerClusterRole(t, tc.manifest)
		for _, g := range metricsAuthGrants {
			if !allowsCreate(role, g.group, g.resource) {
				t.Errorf("%s: ClusterRole %q does not allow create on %s/%s; the secure metrics endpoint returns 500",
					tc.name, controllerClusterRoleName, g.group, g.resource)
			}
		}
	}
}
