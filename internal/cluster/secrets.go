package cluster

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DeployVulnerableSecret() error {

	client, err := GetClient()
	if err != nil {
		return err
	}

	fmt.Println("[*] Deploying vulnerable secret")

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-credentials",
			Namespace: "tenant-a",
		},
		StringData: map[string]string{
			"username": "admin",
			"password": "SuperSecretPassword123",
		},
	}

	_, err = client.CoreV1().
		Secrets("tenant-a").
		Create(context.Background(), secret, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Println("[+] Vulnerable secret created")

	return nil
}
