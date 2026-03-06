package cluster

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ResetLab() error {

	client, err := GetClient()
	if err != nil {
		return err
	}

	namespace := "tenant-a"

	roleBindings := []string{
		"pwn-binding",
		"bind-rbac-manager",
		"bind-token-requestor",
		"bind-pod-creator",
		"bind-exec-operator",
		"bind-cronjob-creator",
		"bind-configmap-editor",
	}

	for _, name := range roleBindings {
		err = client.RbacV1().
			RoleBindings(namespace).
			Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}

	roles := []string{
		"rbac-manager",
		"token-requestor",
		"pod-creator",
		"exec-operator",
		"cronjob-creator",
		"configmap-editor",
	}

	for _, name := range roles {
		err = client.RbacV1().
			Roles(namespace).
			Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}

	pods := []string{
		"token-attacker",
		"escape-attacker",
		"lateral-attacker",
		"victim-app",
		"pod-create-attacker",
		"exec-victim",
		"configmap-victim",
	}

	for _, name := range pods {
		err = client.CoreV1().
			Pods(namespace).
			Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}

	err = client.CoreV1().
		ConfigMaps(namespace).
		Delete(context.Background(), "app-bootstrap", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = client.BatchV1().
		CronJobs(namespace).
		Delete(context.Background(), "persistence-cron", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = client.BatchV1().
		Jobs(namespace).
		Delete(context.Background(), "persistence-cron-manual-run", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = client.CoreV1().
		Pods("tenant-b").
		Delete(context.Background(), "victim-app", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = client.CoreV1().
		Services("tenant-b").
		Delete(context.Background(), "victim-service", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = client.CoreV1().
		Secrets(namespace).
		Delete(context.Background(), "db-credentials", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = DeployVulnerableRBAC()
	if err != nil {
		return err
	}

	return DeployVulnerableSecret()
}
