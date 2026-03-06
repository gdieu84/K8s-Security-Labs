package cluster

import (
	"context"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func GetServiceAccountConfig(namespace, name string) (*rest.Config, error) {
	client, err := GetClient()
	if err != nil {
		return nil, err
	}

	cfg, err := GetConfig()
	if err != nil {
		return nil, err
	}

	expirationSeconds := int64(3600)

	tokenRequest, err := client.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(
			context.Background(),
			name,
			&authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{"https://kubernetes.default.svc"},
					ExpirationSeconds: &expirationSeconds,
				},
			},
			metav1.CreateOptions{},
		)
	if err != nil {
		return nil, err
	}

	serviceAccountConfig := rest.CopyConfig(cfg)
	serviceAccountConfig.BearerToken = tokenRequest.Status.Token
	serviceAccountConfig.BearerTokenFile = ""

	return serviceAccountConfig, nil
}

func GetServiceAccountClient(namespace, name string) (*kubernetes.Clientset, error) {
	cfg, err := GetServiceAccountConfig(namespace, name)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(cfg)
}
