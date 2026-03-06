package attackgraph

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type permissionGrant struct {
	Namespace string
	Verb      string
	APIGroup  string
	Resource  string
	BindingID string
	RoleID    string
}

type podDependencies struct {
	SecretEnvRefs       []string
	SecretVolumeRefs    []string
	ConfigMapEnvRefs    []string
	ConfigMapVolumeRefs []string
}

func Build(ctx context.Context) (*Graph, error) {
	inventory, err := CollectInventory(ctx)
	if err != nil {
		return nil, err
	}

	graph := NewGraph()

	addInventoryNodes(graph, inventory)
	grants := addRBACRelationships(graph, inventory)
	addDerivedRules(graph, inventory, grants)

	return graph, nil
}

func addInventoryNodes(graph *Graph, inventory *Inventory) {
	for _, serviceAccount := range inventory.ServiceAccounts {
		graph.AddNode(Node{
			ID:        serviceAccountNodeID(serviceAccount.Namespace, serviceAccount.Name),
			Kind:      NodeKindServiceAccount,
			Name:      serviceAccount.Name,
			Namespace: serviceAccount.Namespace,
			Label:     fmt.Sprintf("ServiceAccount %s/%s", serviceAccount.Namespace, serviceAccount.Name),
		})
	}

	for _, pod := range inventory.Pods {
		dependencies := podDependenciesForPod(pod)

		graph.AddNode(Node{
			ID:        podNodeID(pod.Namespace, pod.Name),
			Kind:      NodeKindPod,
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Label:     fmt.Sprintf("Pod %s/%s", pod.Namespace, pod.Name),
			Props: map[string]string{
				"secret_env_refs":       strings.Join(dependencies.SecretEnvRefs, ","),
				"secret_volume_refs":    strings.Join(dependencies.SecretVolumeRefs, ","),
				"configmap_env_refs":    strings.Join(dependencies.ConfigMapEnvRefs, ","),
				"configmap_volume_refs": strings.Join(dependencies.ConfigMapVolumeRefs, ","),
			},
		})

		serviceAccountName := pod.Spec.ServiceAccountName
		if serviceAccountName == "" {
			serviceAccountName = "default"
		}

		graph.AddEdge(Edge{
			From:   podNodeID(pod.Namespace, pod.Name),
			To:     serviceAccountNodeID(pod.Namespace, serviceAccountName),
			Kind:   "USES_SERVICEACCOUNT",
			Reason: fmt.Sprintf("Pod %s/%s runs as ServiceAccount %s", pod.Namespace, pod.Name, serviceAccountName),
		})

		for _, secretName := range dependencies.SecretEnvRefs {
			graph.AddEdge(Edge{
				From:   podNodeID(pod.Namespace, pod.Name),
				To:     secretNodeID(pod.Namespace, secretName),
				Kind:   "READS_SECRET_ENV",
				Reason: fmt.Sprintf("Pod %s/%s reads Secret %s via environment variables", pod.Namespace, pod.Name, secretName),
			})
		}

		for _, secretName := range dependencies.SecretVolumeRefs {
			graph.AddEdge(Edge{
				From:   podNodeID(pod.Namespace, pod.Name),
				To:     secretNodeID(pod.Namespace, secretName),
				Kind:   "MOUNTS_SECRET",
				Reason: fmt.Sprintf("Pod %s/%s mounts Secret %s as a volume", pod.Namespace, pod.Name, secretName),
			})
		}

		for _, configMapName := range dependencies.ConfigMapEnvRefs {
			graph.AddEdge(Edge{
				From:   podNodeID(pod.Namespace, pod.Name),
				To:     configMapNodeID(pod.Namespace, configMapName),
				Kind:   "READS_CONFIGMAP_ENV",
				Reason: fmt.Sprintf("Pod %s/%s reads ConfigMap %s via environment variables", pod.Namespace, pod.Name, configMapName),
			})
			graph.AddEdge(Edge{
				From:   configMapNodeID(pod.Namespace, configMapName),
				To:     podNodeID(pod.Namespace, pod.Name),
				Kind:   "INFLUENCES_POD",
				Reason: fmt.Sprintf("ConfigMap %s/%s influences pod %s/%s through environment configuration", pod.Namespace, configMapName, pod.Namespace, pod.Name),
			})
		}

		for _, configMapName := range dependencies.ConfigMapVolumeRefs {
			graph.AddEdge(Edge{
				From:   podNodeID(pod.Namespace, pod.Name),
				To:     configMapNodeID(pod.Namespace, configMapName),
				Kind:   "MOUNTS_CONFIGMAP",
				Reason: fmt.Sprintf("Pod %s/%s mounts ConfigMap %s as a volume", pod.Namespace, pod.Name, configMapName),
			})
			graph.AddEdge(Edge{
				From:   configMapNodeID(pod.Namespace, configMapName),
				To:     podNodeID(pod.Namespace, pod.Name),
				Kind:   "INFLUENCES_POD",
				Reason: fmt.Sprintf("ConfigMap %s/%s influences pod %s/%s through a mounted file", pod.Namespace, configMapName, pod.Namespace, pod.Name),
			})
		}
	}

	for _, secret := range inventory.Secrets {
		graph.AddNode(Node{
			ID:        secretNodeID(secret.Namespace, secret.Name),
			Kind:      NodeKindSecret,
			Name:      secret.Name,
			Namespace: secret.Namespace,
			Label:     fmt.Sprintf("Secret %s/%s", secret.Namespace, secret.Name),
		})
	}

	for _, configMap := range inventory.ConfigMaps {
		graph.AddNode(Node{
			ID:        configMapNodeID(configMap.Namespace, configMap.Name),
			Kind:      NodeKindConfigMap,
			Name:      configMap.Name,
			Namespace: configMap.Namespace,
			Label:     fmt.Sprintf("ConfigMap %s/%s", configMap.Namespace, configMap.Name),
		})
	}

	for _, cronJob := range inventory.CronJobs {
		graph.AddNode(Node{
			ID:        cronJobNodeID(cronJob.Namespace, cronJob.Name),
			Kind:      NodeKindCronJob,
			Name:      cronJob.Name,
			Namespace: cronJob.Namespace,
			Label:     fmt.Sprintf("CronJob %s/%s", cronJob.Namespace, cronJob.Name),
		})

		serviceAccountName := cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName
		if serviceAccountName != "" {
			graph.AddEdge(Edge{
				From:   cronJobNodeID(cronJob.Namespace, cronJob.Name),
				To:     serviceAccountNodeID(cronJob.Namespace, serviceAccountName),
				Kind:   "USES_SERVICEACCOUNT",
				Reason: fmt.Sprintf("CronJob %s/%s runs as ServiceAccount %s", cronJob.Namespace, cronJob.Name, serviceAccountName),
			})
		}
	}

	for _, role := range inventory.Roles {
		graph.AddNode(Node{
			ID:        roleNodeID(role.Namespace, role.Name),
			Kind:      NodeKindRole,
			Name:      role.Name,
			Namespace: role.Namespace,
			Label:     fmt.Sprintf("Role %s/%s", role.Namespace, role.Name),
		})
	}

	for _, roleBinding := range inventory.RoleBindings {
		graph.AddNode(Node{
			ID:        roleBindingNodeID(roleBinding.Namespace, roleBinding.Name),
			Kind:      NodeKindRoleBinding,
			Name:      roleBinding.Name,
			Namespace: roleBinding.Namespace,
			Label:     fmt.Sprintf("RoleBinding %s/%s", roleBinding.Namespace, roleBinding.Name),
		})
	}

	for _, clusterRole := range inventory.ClusterRoles {
		graph.AddNode(Node{
			ID:    clusterRoleNodeID(clusterRole.Name),
			Kind:  NodeKindClusterRole,
			Name:  clusterRole.Name,
			Label: fmt.Sprintf("ClusterRole %s", clusterRole.Name),
		})
	}

	for _, clusterRoleBinding := range inventory.ClusterRoleBindings {
		graph.AddNode(Node{
			ID:    clusterRoleBindingNodeID(clusterRoleBinding.Name),
			Kind:  NodeKindClusterRoleBinding,
			Name:  clusterRoleBinding.Name,
			Label: fmt.Sprintf("ClusterRoleBinding %s", clusterRoleBinding.Name),
		})
	}
}

func addRBACRelationships(graph *Graph, inventory *Inventory) map[string][]permissionGrant {
	grants := make(map[string][]permissionGrant)

	roleIndex := make(map[string]rbacv1.Role)
	for _, role := range inventory.Roles {
		roleIndex[roleNodeID(role.Namespace, role.Name)] = role
	}

	clusterRoleIndex := make(map[string]rbacv1.ClusterRole)
	for _, clusterRole := range inventory.ClusterRoles {
		clusterRoleIndex[clusterRoleNodeID(clusterRole.Name)] = clusterRole
	}

	for _, roleBinding := range inventory.RoleBindings {
		bindingID := roleBindingNodeID(roleBinding.Namespace, roleBinding.Name)
		roleRefID := referencedRoleID(roleBinding.Namespace, roleBinding.RoleRef)

		graph.AddEdge(Edge{
			From:   bindingID,
			To:     roleRefID,
			Kind:   "REFERS_TO_ROLE",
			Reason: fmt.Sprintf("RoleBinding %s/%s references %s %s", roleBinding.Namespace, roleBinding.Name, roleBinding.RoleRef.Kind, roleBinding.RoleRef.Name),
		})

		for _, subject := range roleBinding.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}

			subjectNamespace := subject.Namespace
			if subjectNamespace == "" {
				subjectNamespace = roleBinding.Namespace
			}

			subjectID := serviceAccountNodeID(subjectNamespace, subject.Name)
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     bindingID,
				Kind:   "BOUND_BY",
				Reason: fmt.Sprintf("ServiceAccount %s/%s is bound by RoleBinding %s/%s", subjectNamespace, subject.Name, roleBinding.Namespace, roleBinding.Name),
			})

			for _, grant := range permissionGrantsForRoleRef(roleBinding.Namespace, bindingID, roleRefID, roleBinding.RoleRef, roleIndex, clusterRoleIndex) {
				graph.AddNode(permissionNode(grant.Namespace, grant.APIGroup, grant.Resource, grant.Verb))
				graph.AddEdge(Edge{
					From:   roleRefID,
					To:     permissionNodeID(grant.Namespace, grant.APIGroup, grant.Resource, grant.Verb),
					Kind:   "GRANTS",
					Reason: fmt.Sprintf("%s grants %s on %s", graph.Nodes[roleRefID].Label, grant.Verb, permissionDisplay(grant.APIGroup, grant.Resource, grant.Namespace)),
				})
				graph.AddEdge(Edge{
					From:   subjectID,
					To:     permissionNodeID(grant.Namespace, grant.APIGroup, grant.Resource, grant.Verb),
					Kind:   "HAS_PERMISSION",
					Reason: fmt.Sprintf("%s via %s", graph.Nodes[roleRefID].Label, graph.Nodes[bindingID].Label),
				})
				grants[subjectID] = append(grants[subjectID], grant)
			}
		}
	}

	for _, clusterRoleBinding := range inventory.ClusterRoleBindings {
		bindingID := clusterRoleBindingNodeID(clusterRoleBinding.Name)
		roleRefID := referencedRoleID("", clusterRoleBinding.RoleRef)

		graph.AddEdge(Edge{
			From:   bindingID,
			To:     roleRefID,
			Kind:   "REFERS_TO_ROLE",
			Reason: fmt.Sprintf("ClusterRoleBinding %s references %s %s", clusterRoleBinding.Name, clusterRoleBinding.RoleRef.Kind, clusterRoleBinding.RoleRef.Name),
		})

		for _, subject := range clusterRoleBinding.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}

			subjectID := serviceAccountNodeID(subject.Namespace, subject.Name)
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     bindingID,
				Kind:   "BOUND_BY",
				Reason: fmt.Sprintf("ServiceAccount %s/%s is bound by ClusterRoleBinding %s", subject.Namespace, subject.Name, clusterRoleBinding.Name),
			})

			for _, grant := range permissionGrantsForClusterRoleBinding(bindingID, roleRefID, clusterRoleBinding.RoleRef, clusterRoleIndex) {
				graph.AddNode(permissionNode(grant.Namespace, grant.APIGroup, grant.Resource, grant.Verb))
				graph.AddEdge(Edge{
					From:   roleRefID,
					To:     permissionNodeID(grant.Namespace, grant.APIGroup, grant.Resource, grant.Verb),
					Kind:   "GRANTS",
					Reason: fmt.Sprintf("%s grants %s on %s", graph.Nodes[roleRefID].Label, grant.Verb, permissionDisplay(grant.APIGroup, grant.Resource, grant.Namespace)),
				})
				graph.AddEdge(Edge{
					From:   subjectID,
					To:     permissionNodeID(grant.Namespace, grant.APIGroup, grant.Resource, grant.Verb),
					Kind:   "HAS_PERMISSION",
					Reason: fmt.Sprintf("%s via %s", graph.Nodes[roleRefID].Label, graph.Nodes[bindingID].Label),
				})
				grants[subjectID] = append(grants[subjectID], grant)
			}
		}
	}

	return grants
}

func addDerivedRules(graph *Graph, inventory *Inventory, grants map[string][]permissionGrant) {
	secretsByNamespace := map[string][]corev1.Secret{}
	configMapsByNamespace := map[string][]corev1.ConfigMap{}
	podsByNamespace := map[string][]corev1.Pod{}
	podDependenciesByID := map[string]podDependencies{}
	configMapConsumers := map[string][]string{}

	for _, secret := range inventory.Secrets {
		secretsByNamespace[secret.Namespace] = append(secretsByNamespace[secret.Namespace], secret)
		impactID := impactNodeID(secret.Namespace, "secret-exposure")
		graph.AddNode(impactNode(secret.Namespace, "secret-exposure", "Secret exposure", "90"))
		graph.AddEdge(Edge{
			From:   secretNodeID(secret.Namespace, secret.Name),
			To:     impactID,
			Kind:   "IMPACTS",
			Reason: fmt.Sprintf("Reading Secret %s/%s exposes application credentials", secret.Namespace, secret.Name),
		})
	}

	for _, configMap := range inventory.ConfigMaps {
		configMapsByNamespace[configMap.Namespace] = append(configMapsByNamespace[configMap.Namespace], configMap)
	}

	for _, pod := range inventory.Pods {
		podsByNamespace[pod.Namespace] = append(podsByNamespace[pod.Namespace], pod)
		dependencies := podDependenciesForPod(pod)
		podDependenciesByID[podNodeID(pod.Namespace, pod.Name)] = dependencies

		for _, configMapName := range append([]string{}, dependencies.ConfigMapEnvRefs...) {
			configMapConsumers[configMapNodeID(pod.Namespace, configMapName)] = append(
				configMapConsumers[configMapNodeID(pod.Namespace, configMapName)],
				podNodeID(pod.Namespace, pod.Name),
			)
		}
		for _, configMapName := range dependencies.ConfigMapVolumeRefs {
			configMapConsumers[configMapNodeID(pod.Namespace, configMapName)] = append(
				configMapConsumers[configMapNodeID(pod.Namespace, configMapName)],
				podNodeID(pod.Namespace, pod.Name),
			)
		}
	}

	for _, serviceAccount := range inventory.ServiceAccounts {
		subjectID := serviceAccountNodeID(serviceAccount.Namespace, serviceAccount.Name)
		namespace := serviceAccount.Namespace

		if hasPermission(grants[subjectID], namespace, "create", "rbac.authorization.k8s.io", "rolebindings") {
			capabilityID := capabilityNodeID(namespace, "bind-powerful-role")
			impactID := impactNodeID(namespace, "namespace-admin-equivalent")

			graph.AddNode(capabilityNode(namespace, "bind-powerful-role", "Bind powerful role"))
			graph.AddNode(impactNode(namespace, "namespace-admin-equivalent", "Namespace admin-equivalent", "95"))
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     capabilityID,
				Kind:   "DERIVES",
				Reason: fmt.Sprintf("ServiceAccount %s/%s can create RoleBindings", namespace, serviceAccount.Name),
			})
			graph.AddEdge(Edge{
				From:   capabilityID,
				To:     impactID,
				Kind:   "IMPACTS",
				Reason: fmt.Sprintf("Creating RoleBindings in %s allows binding powerful roles such as cluster-admin", namespace),
			})
		}

		if hasPermission(grants[subjectID], namespace, "create", "", "serviceaccounts/token") {
			capabilityID := capabilityNodeID(namespace, "mint-serviceaccount-token")
			impactID := impactNodeID(namespace, "fresh-serviceaccount-token")

			graph.AddNode(capabilityNode(namespace, "mint-serviceaccount-token", "Mint fresh ServiceAccount token"))
			graph.AddNode(impactNode(namespace, "fresh-serviceaccount-token", "Fresh ServiceAccount token", "70"))
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     capabilityID,
				Kind:   "DERIVES",
				Reason: fmt.Sprintf("ServiceAccount %s/%s can create serviceaccounts/token", namespace, serviceAccount.Name),
			})
			graph.AddEdge(Edge{
				From:   capabilityID,
				To:     impactID,
				Kind:   "IMPACTS",
				Reason: "The attacker can mint new short-lived credentials on demand",
			})
		}

		if hasPermission(grants[subjectID], namespace, "create", "", "pods") {
			createPodCapabilityID := capabilityNodeID(namespace, "create-arbitrary-pod")
			execImpactID := impactNodeID(namespace, "workload-command-execution")
			privilegedCapabilityID := capabilityNodeID(namespace, "create-privileged-hostpath-pod")
			nodeImpactID := impactNodeID(namespace, "node-compromise")

			graph.AddNode(capabilityNode(namespace, "create-arbitrary-pod", "Create arbitrary pod"))
			graph.AddNode(impactNode(namespace, "workload-command-execution", "Workload command execution", "88"))
			graph.AddNode(capabilityNode(namespace, "create-privileged-hostpath-pod", "Create privileged hostPath pod"))
			graph.AddNode(impactNode(namespace, "node-compromise", "Node compromise", "100"))

			graph.AddEdge(Edge{
				From:   subjectID,
				To:     createPodCapabilityID,
				Kind:   "DERIVES",
				Reason: fmt.Sprintf("ServiceAccount %s/%s can create pods", namespace, serviceAccount.Name),
			})
			graph.AddEdge(Edge{
				From:   createPodCapabilityID,
				To:     execImpactID,
				Kind:   "IMPACTS",
				Reason: "Creating arbitrary pods is equivalent to running attacker-controlled code in the namespace",
			})

			for _, secret := range secretsByNamespace[namespace] {
				graph.AddEdge(Edge{
					From:   createPodCapabilityID,
					To:     secretNodeID(secret.Namespace, secret.Name),
					Kind:   "CAN_ACCESS",
					Reason: fmt.Sprintf("A newly created pod in %s can mount Secret %s", namespace, secret.Name),
				})
			}

			graph.AddEdge(Edge{
				From:   createPodCapabilityID,
				To:     privilegedCapabilityID,
				Kind:   "DERIVES",
				Reason: "If admission controls allow it, pod creation can be used to launch a privileged hostPath pod",
			})
			graph.AddEdge(Edge{
				From:   privilegedCapabilityID,
				To:     nodeImpactID,
				Kind:   "IMPACTS",
				Reason: "A privileged pod with hostPath / can access the node filesystem",
			})
		}

		if hasPermission(grants[subjectID], namespace, "get", "", "pods") && hasPermission(grants[subjectID], namespace, "create", "", "pods/exec") {
			capabilityID := capabilityNodeID(namespace, "exec-into-existing-pod")
			impactID := impactNodeID(namespace, "workload-command-execution")
			secretHarvestCapabilityID := capabilityNodeID(namespace, "harvest-workload-secrets")

			graph.AddNode(capabilityNode(namespace, "exec-into-existing-pod", "Exec into existing pod"))
			graph.AddNode(impactNode(namespace, "workload-command-execution", "Workload command execution", "88"))
			graph.AddNode(capabilityNode(namespace, "harvest-workload-secrets", "Harvest workload secrets"))
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     capabilityID,
				Kind:   "DERIVES",
				Reason: fmt.Sprintf("ServiceAccount %s/%s can get pods and create pods/exec", namespace, serviceAccount.Name),
			})
			graph.AddEdge(Edge{
				From:   capabilityID,
				To:     impactID,
				Kind:   "IMPACTS",
				Reason: "pods/exec allows command execution inside existing workloads",
			})

			for _, pod := range podsByNamespace[namespace] {
				podID := podNodeID(pod.Namespace, pod.Name)
				graph.AddEdge(Edge{
					From:   capabilityID,
					To:     podID,
					Kind:   "CAN_ACCESS",
					Reason: fmt.Sprintf("pods/exec can target pod %s/%s", pod.Namespace, pod.Name),
				})

				dependencies := podDependenciesByID[podID]
				if len(dependencies.SecretEnvRefs) > 0 || len(dependencies.SecretVolumeRefs) > 0 {
					graph.AddEdge(Edge{
						From:   capabilityID,
						To:     secretHarvestCapabilityID,
						Kind:   "DERIVES",
						Reason: "pods/exec against workloads with mounted or injected secrets can reveal those credentials",
					})
					for _, secretName := range uniqueStrings(append(append([]string{}, dependencies.SecretEnvRefs...), dependencies.SecretVolumeRefs...)) {
						graph.AddEdge(Edge{
							From:   secretHarvestCapabilityID,
							To:     secretNodeID(pod.Namespace, secretName),
							Kind:   "CAN_ACCESS",
							Reason: fmt.Sprintf("Exec access to pod %s/%s can reveal Secret %s through env vars or mounted files", pod.Namespace, pod.Name, secretName),
						})
					}
				}
			}
		}

		if hasPermission(grants[subjectID], namespace, "create", "batch", "cronjobs") {
			capabilityID := capabilityNodeID(namespace, "establish-persistence")
			impactID := impactNodeID(namespace, "persistence")

			graph.AddNode(capabilityNode(namespace, "establish-persistence", "Establish persistence"))
			graph.AddNode(impactNode(namespace, "persistence", "Persistence", "80"))
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     capabilityID,
				Kind:   "DERIVES",
				Reason: fmt.Sprintf("ServiceAccount %s/%s can create CronJobs", namespace, serviceAccount.Name),
			})
			graph.AddEdge(Edge{
				From:   capabilityID,
				To:     impactID,
				Kind:   "IMPACTS",
				Reason: "CronJobs provide scheduled, durable workload execution in the namespace",
			})
		}

		if hasPermission(grants[subjectID], namespace, "update", "", "configmaps") || hasPermission(grants[subjectID], namespace, "patch", "", "configmaps") {
			capabilityID := capabilityNodeID(namespace, "modify-workload-behavior")
			impactID := impactNodeID(namespace, "config-integrity-compromise")

			graph.AddNode(capabilityNode(namespace, "modify-workload-behavior", "Modify workload behavior"))
			graph.AddNode(impactNode(namespace, "config-integrity-compromise", "Config integrity compromise", "75"))
			graph.AddEdge(Edge{
				From:   subjectID,
				To:     capabilityID,
				Kind:   "DERIVES",
				Reason: fmt.Sprintf("ServiceAccount %s/%s can update or patch ConfigMaps", namespace, serviceAccount.Name),
			})
			for _, configMap := range configMapsByNamespace[namespace] {
				configMapID := configMapNodeID(configMap.Namespace, configMap.Name)
				consumers := uniqueStrings(configMapConsumers[configMapID])
				if len(consumers) == 0 {
					continue
				}

				graph.AddEdge(Edge{
					From:   capabilityID,
					To:     configMapID,
					Kind:   "CAN_ACCESS",
					Reason: fmt.Sprintf("ConfigMap %s/%s can be modified by this identity", configMap.Namespace, configMap.Name),
				})
				for _, consumerID := range consumers {
					graph.AddEdge(Edge{
						From:   configMapID,
						To:     consumerID,
						Kind:   "INFLUENCES_POD",
						Reason: fmt.Sprintf("ConfigMap %s/%s is consumed by %s", configMap.Namespace, configMap.Name, graph.NodeLabel(consumerID)),
					})
				}
				graph.AddEdge(Edge{
					From:   configMapID,
					To:     impactID,
					Kind:   "IMPACTS",
					Reason: fmt.Sprintf("ConfigMap %s/%s is consumed by running workloads, so tampering can alter startup behavior", configMap.Namespace, configMap.Name),
				})
			}
		}
	}
}

func podDependenciesForPod(pod corev1.Pod) podDependencies {
	dependencies := podDependencies{
		SecretEnvRefs:       []string{},
		SecretVolumeRefs:    []string{},
		ConfigMapEnvRefs:    []string{},
		ConfigMapVolumeRefs: []string{},
	}

	secretEnvRefs := map[string]bool{}
	secretVolumeRefs := map[string]bool{}
	configMapEnvRefs := map[string]bool{}
	configMapVolumeRefs := map[string]bool{}

	allContainers := append([]corev1.Container{}, pod.Spec.InitContainers...)
	allContainers = append(allContainers, pod.Spec.Containers...)

	for _, container := range allContainers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				secretEnvRefs[env.ValueFrom.SecretKeyRef.Name] = true
			}
			if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
				configMapEnvRefs[env.ValueFrom.ConfigMapKeyRef.Name] = true
			}
		}
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil {
				secretEnvRefs[envFrom.SecretRef.Name] = true
			}
			if envFrom.ConfigMapRef != nil {
				configMapEnvRefs[envFrom.ConfigMapRef.Name] = true
			}
		}
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil {
			secretVolumeRefs[volume.Secret.SecretName] = true
		}
		if volume.ConfigMap != nil {
			configMapVolumeRefs[volume.ConfigMap.Name] = true
		}
	}

	dependencies.SecretEnvRefs = sortedKeys(secretEnvRefs)
	dependencies.SecretVolumeRefs = sortedKeys(secretVolumeRefs)
	dependencies.ConfigMapEnvRefs = sortedKeys(configMapEnvRefs)
	dependencies.ConfigMapVolumeRefs = sortedKeys(configMapVolumeRefs)

	return dependencies
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))

	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}

	sort.Strings(out)

	return out
}

func permissionGrantsForRoleRef(namespace, bindingID, roleID string, roleRef rbacv1.RoleRef, roles map[string]rbacv1.Role, clusterRoles map[string]rbacv1.ClusterRole) []permissionGrant {
	switch roleRef.Kind {
	case "Role":
		role, exists := roles[roleID]
		if !exists {
			return nil
		}
		return expandPolicyRules(namespace, bindingID, roleID, role.Rules)
	case "ClusterRole":
		clusterRole, exists := clusterRoles[roleID]
		if !exists {
			return nil
		}
		return expandPolicyRules(namespace, bindingID, roleID, clusterRole.Rules)
	default:
		return nil
	}
}

func permissionGrantsForClusterRoleBinding(bindingID, roleID string, roleRef rbacv1.RoleRef, clusterRoles map[string]rbacv1.ClusterRole) []permissionGrant {
	if roleRef.Kind != "ClusterRole" {
		return nil
	}

	clusterRole, exists := clusterRoles[roleID]
	if !exists {
		return nil
	}

	return expandPolicyRules("*", bindingID, roleID, clusterRole.Rules)
}

func expandPolicyRules(namespace, bindingID, roleID string, rules []rbacv1.PolicyRule) []permissionGrant {
	grants := make([]permissionGrant, 0)

	for _, rule := range rules {
		apiGroups := rule.APIGroups
		if len(apiGroups) == 0 {
			apiGroups = []string{""}
		}

		for _, apiGroup := range apiGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					grants = append(grants, permissionGrant{
						Namespace: namespace,
						Verb:      verb,
						APIGroup:  apiGroup,
						Resource:  resource,
						BindingID: bindingID,
						RoleID:    roleID,
					})
				}
			}
		}
	}

	return grants
}

func hasPermission(grants []permissionGrant, namespace, verb, apiGroup, resource string) bool {
	for _, grant := range grants {
		namespaceMatch := grant.Namespace == "*" || grant.Namespace == namespace
		verbMatch := grant.Verb == "*" || grant.Verb == verb
		apiGroupMatch := grant.APIGroup == "*" || grant.APIGroup == apiGroup
		resourceMatch := grant.Resource == "*" || grant.Resource == resource

		if namespaceMatch && verbMatch && apiGroupMatch && resourceMatch {
			return true
		}
	}

	return false
}

func serviceAccountNodeID(namespace, name string) string {
	return "sa:" + namespace + "/" + name
}

func podNodeID(namespace, name string) string {
	return "pod:" + namespace + "/" + name
}

func roleNodeID(namespace, name string) string {
	return "role:" + namespace + "/" + name
}

func roleBindingNodeID(namespace, name string) string {
	return "rolebinding:" + namespace + "/" + name
}

func clusterRoleNodeID(name string) string {
	return "clusterrole:" + name
}

func clusterRoleBindingNodeID(name string) string {
	return "clusterrolebinding:" + name
}

func secretNodeID(namespace, name string) string {
	return "secret:" + namespace + "/" + name
}

func configMapNodeID(namespace, name string) string {
	return "configmap:" + namespace + "/" + name
}

func cronJobNodeID(namespace, name string) string {
	return "cronjob:" + namespace + "/" + name
}

func permissionNodeID(namespace, apiGroup, resource, verb string) string {
	scope := namespace
	if scope == "" {
		scope = "cluster"
	}

	return "permission:" + scope + ":" + apiGroup + ":" + resource + ":" + verb
}

func permissionNode(namespace, apiGroup, resource, verb string) Node {
	scopeLabel := namespace
	if scopeLabel == "*" {
		scopeLabel = "all-namespaces"
	} else if scopeLabel == "" {
		scopeLabel = "cluster"
	}

	return Node{
		ID:    permissionNodeID(namespace, apiGroup, resource, verb),
		Kind:  NodeKindPermission,
		Name:  fmt.Sprintf("%s %s", verb, resource),
		Label: fmt.Sprintf("Permission %s on %s (%s)", verb, permissionDisplay(apiGroup, resource, namespace), scopeLabel),
		Props: map[string]string{
			"verb":     verb,
			"resource": resource,
			"apiGroup": apiGroup,
			"scope":    scopeLabel,
		},
	}
}

func capabilityNodeID(namespace, key string) string {
	return "capability:" + namespace + ":" + key
}

func capabilityNode(namespace, key, label string) Node {
	return Node{
		ID:        capabilityNodeID(namespace, key),
		Kind:      NodeKindCapability,
		Name:      key,
		Namespace: namespace,
		Label:     fmt.Sprintf("Capability %s (%s)", label, namespace),
	}
}

func impactNodeID(namespace, key string) string {
	return "impact:" + namespace + ":" + key
}

func impactNode(namespace, key, label, severity string) Node {
	return Node{
		ID:        impactNodeID(namespace, key),
		Kind:      NodeKindImpact,
		Name:      key,
		Namespace: namespace,
		Label:     fmt.Sprintf("Impact %s (%s)", label, namespace),
		Props: map[string]string{
			"severity": severity,
		},
	}
}

func referencedRoleID(bindingNamespace string, roleRef rbacv1.RoleRef) string {
	if roleRef.Kind == "ClusterRole" {
		return clusterRoleNodeID(roleRef.Name)
	}

	return roleNodeID(bindingNamespace, roleRef.Name)
}

func permissionDisplay(apiGroup, resource, namespace string) string {
	resourceLabel := resource
	if apiGroup != "" {
		resourceLabel = apiGroup + "/" + resourceLabel
	}
	if namespace == "*" {
		return resourceLabel + " in all namespaces"
	}
	if namespace == "" {
		return resourceLabel + " cluster-wide"
	}

	return resourceLabel + " in namespace " + namespace
}

func ParseNodeReference(ref string) string {
	switch {
	case strings.HasPrefix(ref, "sa:"):
		return ref
	case strings.HasPrefix(ref, "pod:"):
		return ref
	default:
		return ref
	}
}
