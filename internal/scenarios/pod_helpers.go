package scenarios

import (
	"context"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func waitForPodCompletion(client *kubernetes.Clientset, namespace, podName string, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		pod, err := client.CoreV1().
			Pods(namespace).
			Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		switch pod.Status.Phase {
		case corev1.PodSucceeded, corev1.PodRunning:
			return pod, nil
		case corev1.PodFailed:
			return pod, fmt.Errorf("pod %s failed", podName)
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timed out waiting for pod %s", podName)
}

func getPodLogs(client *kubernetes.Clientset, namespace, podName string) (string, error) {
	stream, err := client.CoreV1().
		Pods(namespace).
		GetLogs(podName, &corev1.PodLogOptions{}).
		Stream(context.Background())
	if err != nil {
		return "", err
	}
	defer stream.Close()

	logs, err := io.ReadAll(stream)
	if err != nil {
		return "", err
	}

	return string(logs), nil
}

func waitForJobPod(client *kubernetes.Clientset, namespace, jobName string, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		pods, err := client.CoreV1().
			Pods(namespace).
			List(context.Background(), metav1.ListOptions{
				LabelSelector: "job-name=" + jobName,
			})
		if err != nil {
			return nil, err
		}

		if len(pods.Items) == 0 {
			time.Sleep(2 * time.Second)
			continue
		}

		return waitForPodCompletion(client, namespace, pods.Items[0].Name, timeout)
	}

	return nil, fmt.Errorf("timed out waiting for a pod for job %s", jobName)
}
