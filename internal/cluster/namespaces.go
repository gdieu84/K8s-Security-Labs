package cluster

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateNamespace(name string) error {

	client, err := GetClient()
	if err != nil {
		return err
	}

	ns, err := client.CoreV1().
		Namespaces().
		Get(context.Background(), name, metav1.GetOptions{})

	if err == nil {

		if ns.Status.Phase == corev1.NamespaceTerminating {

			fmt.Printf("[*] Namespace %s is terminating, waiting...\n", name)

			for {

				time.Sleep(2 * time.Second)

				_, err := client.CoreV1().
					Namespaces().
					Get(context.Background(), name, metav1.GetOptions{})

				if apierrors.IsNotFound(err) {
					break
				}
			}

		} else {

			fmt.Printf("[*] Namespace %s already exists\n", name)
			return nil
		}
	}

	fmt.Printf("[*] Creating namespace: %s\n", name)

	newNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	_, err = client.CoreV1().
		Namespaces().
		Create(context.Background(), newNS, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Printf("[+] Namespace %s created\n", name)

	return nil
}
