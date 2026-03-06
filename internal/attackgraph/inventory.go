package attackgraph

import (
	"context"

	"k8s-security-lab/internal/cluster"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Inventory struct {
	Pods                []corev1.Pod
	ServiceAccounts     []corev1.ServiceAccount
	Secrets             []corev1.Secret
	ConfigMaps          []corev1.ConfigMap
	CronJobs            []batchv1.CronJob
	Roles               []rbacv1.Role
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoles        []rbacv1.ClusterRole
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
}

func CollectInventory(ctx context.Context) (*Inventory, error) {
	client, err := cluster.GetClient()
	if err != nil {
		return nil, err
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	serviceAccounts, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	configMaps, err := client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	cronJobs, err := client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	roles, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	roleBindings, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return &Inventory{
		Pods:                pods.Items,
		ServiceAccounts:     serviceAccounts.Items,
		Secrets:             secrets.Items,
		ConfigMaps:          configMaps.Items,
		CronJobs:            cronJobs.Items,
		Roles:               roles.Items,
		RoleBindings:        roleBindings.Items,
		ClusterRoles:        clusterRoles.Items,
		ClusterRoleBindings: clusterRoleBindings.Items,
	}, nil
}
