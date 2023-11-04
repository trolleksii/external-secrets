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

package ghcr

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGenerate(t *testing.T) {
	type args struct {
		ctx              context.Context
		jsonSpec         *apiextensions.JSON
		kube             client.Client
		namespace        string
		fakeTokenFetcher accessTokenFetcher
	}
	tests := []struct {
		name    string
		g       *Generator
		args    args
		want    map[string][]byte
		wantErr bool
	}{
		{
			name: "no spec",
			args: args{
				jsonSpec: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid json",
			args: args{
				jsonSpec: &apiextensions.JSON{
					Raw: []byte(``),
				},
			},
			wantErr: true,
		},
		{
			name: "spec with values produces valus",
			args: args{
				namespace: "foobar",
				kube: clientfake.NewClientBuilder().WithObjects(&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example",
						Namespace: "foobar",
					},
					Data: map[string][]byte{
						"key.pem": func() []byte {
							key, _ := rsa.GenerateKey(rand.Reader, 2048)
							return pem.EncodeToMemory(
								&pem.Block{
									Type:  "RSA PRIVATE KEY",
									Bytes: x509.MarshalPKCS1PrivateKey(key),
								},
							)
						}(),
					},
				}).Build(),
				jsonSpec: &apiextensions.JSON{
					Raw: []byte(`apiVersion: generators.external-secrets.io/v1alpha1
kind: GHCRAccessToken
spec:
  appID: 12345
  installationID: 1234567
  privateKeySecretRef:
    secretAccessKeySecretRef:
      name: "example"
      key: "key.pem"
`),
				},
				fakeTokenFetcher: func(_ string, _ int, _ string) (*installationAccessToken, error) {
					return &installationAccessToken{
						Token:  "token",
						Expiry: "somedate",
					}, nil
				},
			},
			want: map[string][]byte{
				"username": []byte("x-access-token"),
				"password": []byte("token"),
				"expiry":   []byte("somedate"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Generator{}
			got, err := g.generate(
				tt.args.ctx,
				tt.args.jsonSpec,
				tt.args.kube,
				tt.args.namespace,
				tt.args.fakeTokenFetcher,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Generator.Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}
