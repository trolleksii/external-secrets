/*
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

package v1alpha1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type GHCRAccessTokenSpec struct {
	// Github App ID
	AppID int `json:"appID"`
	// Github App Installation ID.
	InstallationID int `json:"installationID"`
	// Secret referencet to the Github App private key
	PrivateKeySecretRef esmeta.SecretKeySelector `json:"privateKeySecretRef"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={ghcraccesstoken},shortName=ghcraccesstoken
type GHCRAccessToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GHCRAccessTokenSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true
type GHCRAccessTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GHCRAccessToken `json:"items"`
}
