package attackgraph

import "sort"

var capabilityScenarioMap = map[string]ScenarioRecommendation{
	"bind-powerful-role": {
		ID:      "rbac",
		Command: "lab-cli attack rbac",
		Reason:  "This path depends on RoleBinding-based privilege escalation.",
	},
	"mint-serviceaccount-token": {
		ID:      "token-request",
		Command: "lab-cli attack token-request",
		Reason:  "This path depends on TokenRequest abuse for a ServiceAccount.",
	},
	"create-arbitrary-pod": {
		ID:      "pod-create",
		Command: "lab-cli attack pod-create",
		Reason:  "This path depends on creating attacker-controlled pods.",
	},
	"create-privileged-hostpath-pod": {
		ID:      "escape",
		Command: "lab-cli attack escape",
		Reason:  "This path depends on launching a privileged hostPath pod.",
	},
	"exec-into-existing-pod": {
		ID:      "exec",
		Command: "lab-cli attack exec",
		Reason:  "This path depends on `pods/exec` against a workload.",
	},
	"harvest-workload-secrets": {
		ID:      "exec",
		Command: "lab-cli attack exec",
		Reason:  "This path uses exec access to recover application secrets.",
	},
	"establish-persistence": {
		ID:      "cronjob",
		Command: "lab-cli attack cronjob",
		Reason:  "This path depends on scheduled workload persistence.",
	},
	"modify-workload-behavior": {
		ID:      "configmap-poison",
		Command: "lab-cli attack configmap-poison",
		Reason:  "This path depends on modifying a consumed ConfigMap.",
	},
}

var impactScenarioMap = map[string]ScenarioRecommendation{
	"fresh-serviceaccount-token": {
		ID:      "token-request",
		Command: "lab-cli attack token-request",
		Reason:  "This impact is demonstrated by minting a fresh token.",
	},
	"node-compromise": {
		ID:      "escape",
		Command: "lab-cli attack escape",
		Reason:  "This impact is demonstrated by the escape scenario.",
	},
	"persistence": {
		ID:      "cronjob",
		Command: "lab-cli attack cronjob",
		Reason:  "This impact is demonstrated by the CronJob persistence scenario.",
	},
	"config-integrity-compromise": {
		ID:      "configmap-poison",
		Command: "lab-cli attack configmap-poison",
		Reason:  "This impact is demonstrated by ConfigMap poisoning.",
	},
	"namespace-admin-equivalent": {
		ID:      "rbac",
		Command: "lab-cli attack rbac",
		Reason:  "This impact is demonstrated by RoleBinding escalation.",
	},
	"secret-exposure": {
		ID:      "secrets",
		Command: "lab-cli attack secrets",
		Reason:  "This impact is demonstrated by the secrets exposure scenario.",
	},
	"workload-command-execution": {
		ID:      "exec",
		Command: "lab-cli attack exec",
		Reason:  "This impact is demonstrated by the exec scenario.",
	},
}

func RecommendScenarios(path AttackPath, graph *Graph) []ScenarioRecommendation {
	recommendations := map[string]ScenarioRecommendation{}

	for _, edge := range path.Edges {
		target, exists := graph.Nodes[edge.To]
		if !exists {
			continue
		}

		if target.Kind == NodeKindCapability {
			if recommendation, exists := capabilityScenarioMap[target.Name]; exists {
				recommendations[recommendation.ID] = recommendation
			}
		}
	}

	goalNode, exists := graph.Nodes[path.Goal]
	if exists && goalNode.Kind == NodeKindImpact {
		if recommendation, found := impactScenarioMap[goalNode.Name]; found {
			recommendations[recommendation.ID] = recommendation
		}
	}

	ids := make([]string, 0, len(recommendations))
	for id := range recommendations {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	ordered := make([]ScenarioRecommendation, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, recommendations[id])
	}

	return ordered
}
