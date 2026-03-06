package cluster

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func DeployVulnerableRBAC() error {

	client, err := GetClient()
	if err != nil {
		return err
	}

	namespace := "tenant-a"

	roles := []*rbacv1.Role{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rbac-manager",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"rbac.authorization.k8s.io"},
					Resources: []string{"rolebindings"},
					Verbs:     []string{"create"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "token-requestor",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts/token"},
					Verbs:     []string{"create"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-creator",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"create"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "exec-operator",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"pods/exec"},
					Verbs:     []string{"create"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cronjob-creator",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"batch"},
					Resources: []string{"cronjobs"},
					Verbs:     []string{"create"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "configmap-editor",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Verbs:     []string{"get", "update", "patch"},
				},
			},
		},
	}

	for _, role := range roles {
		err = applyRole(client, role)
		if err != nil {
			return err
		}
	}

	bindings := []*rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bind-rbac-manager",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "rbac-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bind-token-requestor",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "token-requestor",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bind-pod-creator",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "pod-creator",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bind-exec-operator",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "exec-operator",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bind-cronjob-creator",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "cronjob-creator",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bind-configmap-editor",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "tenant-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "configmap-editor",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}

	for _, binding := range bindings {
		err = applyRoleBinding(client, binding)
		if err != nil {
			return err
		}
	}

	return nil
}

func applyRole(client *kubernetes.Clientset, role *rbacv1.Role) error {
	_, err := client.RbacV1().
		Roles(role.Namespace).
		Create(context.Background(), role, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}

	current, getErr := client.RbacV1().
		Roles(role.Namespace).
		Get(context.Background(), role.Name, metav1.GetOptions{})
	if getErr != nil {
		return getErr
	}

	role.ResourceVersion = current.ResourceVersion

	_, err = client.RbacV1().
		Roles(role.Namespace).
		Update(context.Background(), role, metav1.UpdateOptions{})

	return err
}

func applyRoleBinding(client *kubernetes.Clientset, binding *rbacv1.RoleBinding) error {
	_, err := client.RbacV1().
		RoleBindings(binding.Namespace).
		Create(context.Background(), binding, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}

	current, getErr := client.RbacV1().
		RoleBindings(binding.Namespace).
		Get(context.Background(), binding.Name, metav1.GetOptions{})
	if getErr != nil {
		return getErr
	}

	binding.ResourceVersion = current.ResourceVersion

	_, err = client.RbacV1().
		RoleBindings(binding.Namespace).
		Update(context.Background(), binding, metav1.UpdateOptions{})

	return err
}
