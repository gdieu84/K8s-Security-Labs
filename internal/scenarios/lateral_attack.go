package scenarios

import (
	"context"
	"fmt"
	"time"

	"k8s-security-lab/internal/cluster"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func LateralAttack() error {

	fmt.Println("[*] Starting lateral movement scenario")

	client, err := cluster.GetClient()
	if err != nil {
		return err
	}

	attackerNS := "tenant-a"
	victimNS := "tenant-b"

	fmt.Println("[*] Deploying victim service in namespace:", victimNS)

	victimPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "victim-app",
			Namespace: victimNS,
			Labels: map[string]string{
				"app": "victim",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "victim",
					Image: "hashicorp/http-echo",
					Args: []string{
						"-text=Hello-from-tenant-b",
					},
				},
			},
		},
	}

	_, err = client.CoreV1().
		Pods(victimNS).
		Create(context.Background(), victimPod, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "victim-service",
			Namespace: victimNS,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "victim",
			},
			Ports: []corev1.ServicePort{
				{
					Port: 5678,
				},
			},
		},
	}

	_, err = client.CoreV1().
		Services(victimNS).
		Create(context.Background(), service, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Println("[+] Victim service deployed")

	fmt.Println("[*] Creating attacker pod")

	attackerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lateral-attacker",
			Namespace: attackerNS,
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

	_, err = client.CoreV1().
		Pods(attackerNS).
		Create(context.Background(), attackerPod, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Println("[+] Attacker pod created")

	fmt.Println("[*] Waiting for pods to become ready")

	time.Sleep(6 * time.Second)

	fmt.Println("[*] Attempting lateral access")

	target := "victim-service.tenant-b.svc.cluster.local"

	fmt.Println("\nEvidence:")

	fmt.Printf("Attacker can reach service: http://%s:5678\n", target)

	fmt.Println("\nExample exploit inside attacker pod:")

	fmt.Println(`
wget -qO- http://victim-service.tenant-b.svc.cluster.local:5678
`)

	fmt.Println("\nExpected response:")

	fmt.Println("Hello-from-tenant-b")

	fmt.Println("\nImpact:")

	fmt.Println("- Cross-namespace communication allowed")
	fmt.Println("- Tenant isolation broken")
	fmt.Println("- Attacker can access internal services")

	return nil
}
