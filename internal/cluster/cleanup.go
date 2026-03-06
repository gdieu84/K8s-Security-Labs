package cluster

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DestroyLab() error {

	fmt.Println("[*] Destroying Kubernetes security lab")

	client, err := GetClient()
	if err != nil {
		return err
	}

	namespaces := []string{
		"tenant-a",
		"tenant-b",
	}

	for _, ns := range namespaces {

		fmt.Printf("[*] Deleting namespace: %s\n", ns)

		err := client.CoreV1().
			Namespaces().
			Delete(context.Background(), ns, metav1.DeleteOptions{})

		if err != nil {
			fmt.Printf("[!] Failed to delete namespace %s: %v\n", ns, err)
			continue
		}

		fmt.Printf("[+] Namespace %s deletion requested\n", ns)
	}

	fmt.Println("[+] Lab environment cleanup completed")

	return nil
}
