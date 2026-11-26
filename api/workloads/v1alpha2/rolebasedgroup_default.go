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

package v1alpha2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// roleBasedGroupMutatingPath is where the kubebuilder:webhook marker in
// rolebasedgroup_webhook.go points the mutating webhook configuration.
const roleBasedGroupMutatingPath = "/mutate-workloads-x-k8s-io-v1alpha2-rolebasedgroup"

// roleBasedGroupDefaultingHandler serves the RoleBasedGroup mutating webhook and
// patches only what RoleBasedGroupDefaulter changes.
//
// The handler controller-runtime builds for a CustomDefaulter diffs the request
// against the whole object re-encoded from the typed struct, so it also writes back
// every field the struct cannot omit. An inline Pod template stored without a spec
// gains "spec: {containers: null}", which fails schema validation, so no write to
// such a RoleBasedGroup is admitted any more (#627). Diffing the typed object before
// and after defaulting leaves everything the defaulter did not touch as it was sent.
type roleBasedGroupDefaultingHandler struct {
	decoder   admission.Decoder
	defaulter *RoleBasedGroupDefaulter
}

// Handle implements admission.Handler.
func (h *roleBasedGroupDefaultingHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return admission.Allowed("")
	}
	rbg := &RoleBasedGroup{}
	if err := h.decoder.Decode(req, rbg); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	before, err := json.Marshal(rbg)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if err := h.defaulter.Default(admission.NewContextWithRequest(ctx, req), rbg); err != nil {
		return admission.Denied(err.Error())
	}
	after, err := json.Marshal(rbg)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	patches, err := jsonpatch.CreatePatch(before, after)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if len(patches) == 0 {
		return admission.Allowed("")
	}
	return admission.Patched("", patches...)
}

// RoleBasedGroupDefaulter normalizes legacy update-strategy type values on
// RoleBasedGroup writes. Objects stored before the rollingUpdate.type enum was
// introduced can carry "" or the v1alpha1 "Recreate" spelling; normalizing them
// here keeps such objects writable instead of failing schema validation.
//
// +kubebuilder:object:generate=false
type RoleBasedGroupDefaulter struct{}

var _ admission.CustomDefaulter = &RoleBasedGroupDefaulter{}

// Default implements admission.CustomDefaulter.
func (d *RoleBasedGroupDefaulter) Default(_ context.Context, obj runtime.Object) error {
	rbg, ok := obj.(*RoleBasedGroup)
	if !ok {
		return fmt.Errorf("expected *RoleBasedGroup but got %T", obj)
	}
	for i := range rbg.Spec.Roles {
		ru := rbg.Spec.Roles[i].RolloutStrategy
		if ru == nil || ru.RollingUpdate == nil {
			continue
		}
		ru.RollingUpdate.Type = NormalizeUpdateStrategyType(ru.RollingUpdate.Type)
	}
	return nil
}
