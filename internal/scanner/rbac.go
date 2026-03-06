package scanner

import (
	"context"
	"fmt"

	"k8s-security-lab/internal/cluster"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ScanRBAC() error {

	client, err := cluster.GetClient()
	if err != nil {
		return err
	}

	roles, err := client.RbacV1().
		Roles("").
		List(context.Background(), metav1.ListOptions{})

	if err != nil {
		return err
	}

	for _, role := range roles.Items {

		for _, rule := range role.Rules {

			for _, verb := range rule.Verbs {

				if verb == "create" {

					fmt.Printf("⚠ Role '%s' in namespace '%s' can create resources\n",
						role.Name,
						role.Namespace)
				}
			}
		}
	}

	return nil
}
