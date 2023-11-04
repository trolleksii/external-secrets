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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

type Generator struct{}

const (
	errNoSpec       = "no config spec provided"
	errParseSpec    = "unable to parse spec: %w"
	errParseSecret  = "key %s not found in secret %s"
	errSecretNotSet = "unable to get private key: secret name or key not set"
	errGetToken     = "unable to get authorization token: %w"
)

type installationAccessToken struct {
	Token  string `json:"token"`
	Expiry string `json:"expires_at"`
}

func (g *Generator) Generate(ctx context.Context, jsonSpec *apiextensions.JSON, kube client.Client, namespace string) (map[string][]byte, error) {
	return g.generate(ctx, jsonSpec, kube, namespace, fetchInstallationAccessToken)
}

func (g *Generator) generate(ctx context.Context, jsonSpec *apiextensions.JSON, kube client.Client, namespace string, tokenFetcher accessTokenFetcher) (map[string][]byte, error) {
	if jsonSpec == nil {
		return nil, fmt.Errorf(errNoSpec)
	}
	res, err := parseSpec(jsonSpec.Raw)
	if err != nil {
		return nil, fmt.Errorf(errParseSpec, err)
	}

	if res.Spec.PrivateKeySecretRef.Name == "" || res.Spec.PrivateKeySecretRef.Key == "" {
		return nil, fmt.Errorf(errSecretNotSet)
	}

	secret := &corev1.Secret{}

	objectKey := client.ObjectKey{
		Namespace: namespace,
		Name:      res.Spec.PrivateKeySecretRef.Name,
	}

	if err := kube.Get(ctx, objectKey, secret); err != nil {
		return nil, err
	}

	data, ok := secret.Data[res.Spec.PrivateKeySecretRef.Key]
	if !ok {
		return nil, fmt.Errorf(errParseSecret, res.Spec.PrivateKeySecretRef.Key, res.Spec.PrivateKeySecretRef.Name)
	}

	rsaKey, err := parseRSAPrivateKey(data)
	if err != nil {
		return nil, err
	}

	appToken, err := newGithubAppToken(res.Spec.AppID, res.Spec.TokenLifetime, rsaKey)
	if err != nil {
		return nil, err
	}

	accessToken, err := tokenFetcher(res.Spec.GithubAPIURL, res.Spec.InstallationID, appToken)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"username": []byte("x-access-token"),
		"password": []byte(accessToken.Token),
		"expiry":   []byte(accessToken.Expiry),
	}, nil
}

type accessTokenFetcher func(apiURL string, installationID int, jwt string) (*installationAccessToken, error)

func fetchInstallationAccessToken(apiURL string, installationID int, jwt string) (*installationAccessToken, error) {
	url := apiURL
	if !strings.HasSuffix(apiURL, "/") {
		url = fmt.Sprintf("%s/", apiURL)
	}
	client := &http.Client{}
	req, _ := http.NewRequest("POST", fmt.Sprintf("%sapp/installations/%d/access_tokens", url, installationID), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt))
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	token := &installationAccessToken{}

	if err := json.Unmarshal(bodyBytes, token); err != nil {
		return nil, err
	}
	return token, nil
}

func newGithubAppToken(appID int, lifetime metav1.Duration, privateKey *rsa.PrivateKey) (string, error) {
	iat := time.Now()
	exp := iat.Add(lifetime.Duration)
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": appID,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
	}).SignedString(privateKey)

	if err != nil {
		return "", err
	}
	return token, nil
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	keyPem, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return keyPem, nil
}

func parseSpec(data []byte) (*genv1alpha1.GHCRAccessToken, error) {
	var spec genv1alpha1.GHCRAccessToken
	err := yaml.Unmarshal(data, &spec)
	return &spec, err
}

func init() {
	genv1alpha1.Register(genv1alpha1.GHCRAccessTokenKind, &Generator{})
}
