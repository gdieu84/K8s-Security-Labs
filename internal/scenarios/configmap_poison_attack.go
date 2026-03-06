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

func ConfigMapPoisonAttack() error {
	fmt.Println("[*] Starting ConfigMap poisoning scenario")

	namespace := "tenant-a"
	serviceAccountName := "tenant-sa"
	configMapName := "app-bootstrap"
	podName := "configmap-victim"

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

	err = adminClient.CoreV1().
		ConfigMaps(namespace).
		Delete(context.Background(), configMapName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			"run.sh": "#!/bin/sh\necho status=benign\necho source=configmap\n",
		},
	}

	configMap, err = adminClient.CoreV1().
		ConfigMaps(namespace).
		Create(context.Background(), configMap, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	fmt.Println("[*] Deploying victim pod that executes a script from the ConfigMap")

	_, err = adminClient.CoreV1().
		Pods(namespace).
		Create(context.Background(), configMapVictimPod(namespace, podName), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = waitForPodCompletion(adminClient, namespace, podName, 45*time.Second)
	if err != nil {
		return err
	}

	beforeLogs, err := getPodLogs(adminClient, namespace, podName)
	if err != nil {
		return err
	}

	fmt.Printf("[*] Using compromised %s/%s identity to modify the ConfigMap\n", namespace, serviceAccountName)

	configMap.Data["run.sh"] = "#!/bin/sh\necho status=poisoned\necho action=malicious-bootstrap\n"

	_, err = compromisedClient.CoreV1().
		ConfigMaps(namespace).
		Update(context.Background(), configMap, metav1.UpdateOptions{})
	if err != nil {
		fmt.Println("[!] ConfigMap update failed")
		fmt.Println("\nEvidence:")
		fmt.Println(err)
		return err
	}

	err = adminClient.CoreV1().
		Pods(namespace).
		Delete(context.Background(), podName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	_, err = adminClient.CoreV1().
		Pods(namespace).
		Create(context.Background(), configMapVictimPod(namespace, podName), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = waitForPodCompletion(adminClient, namespace, podName, 45*time.Second)
	if err != nil {
		return err
	}

	afterLogs, err := getPodLogs(adminClient, namespace, podName)
	if err != nil {
		return err
	}

	fmt.Println("\nEvidence:")
	fmt.Println("Before poisoning:")
	fmt.Println(strings.TrimSpace(beforeLogs))
	fmt.Println("\nAfter poisoning:")
	fmt.Println(strings.TrimSpace(afterLogs))

	fmt.Println("\nImpact:")
	fmt.Println("- Attacker can tamper with workload configuration or bootstrap scripts")
	fmt.Println("- A restart or rollout can turn config integrity issues into code execution")
	fmt.Println("- Config objects should be treated as sensitive control-plane data")

	return nil
}

func configMapVictimPod(namespace, podName string) *corev1.Pod {
	executableMode := int32(0755)

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "victim",
					Image: "alpine",
					Command: []string{
						"/config/run.sh",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "bootstrap",
							MountPath: "/config",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "bootstrap",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "app-bootstrap",
							},
							DefaultMode: &executableMode,
						},
					},
				},
			},
		},
	}
}
