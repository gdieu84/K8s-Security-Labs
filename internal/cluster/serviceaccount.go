package cluster

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateTenantServiceAccount(namespace string) error {

	client, err := GetClient()
	if err != nil {
		return err
	}

	fmt.Printf("[*] Creating ServiceAccount: %s/tenant-sa\n", namespace)

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tenant-sa",
			Namespace: namespace,
		},
	}

	_, err = client.CoreV1().
		ServiceAccounts(namespace).
		Create(context.Background(), sa, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Println("[+] ServiceAccount created")

	return nil
}
