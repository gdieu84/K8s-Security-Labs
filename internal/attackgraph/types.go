package attackgraph

type NodeKind string

const (
	NodeKindPod                NodeKind = "Pod"
	NodeKindServiceAccount     NodeKind = "ServiceAccount"
	NodeKindRole               NodeKind = "Role"
	NodeKindClusterRole        NodeKind = "ClusterRole"
	NodeKindRoleBinding        NodeKind = "RoleBinding"
	NodeKindClusterRoleBinding NodeKind = "ClusterRoleBinding"
	NodeKindPermission         NodeKind = "Permission"
	NodeKindCapability         NodeKind = "Capability"
	NodeKindSecret             NodeKind = "Secret"
	NodeKindConfigMap          NodeKind = "ConfigMap"
	NodeKindCronJob            NodeKind = "CronJob"
	NodeKindImpact             NodeKind = "Impact"
)

type Node struct {
	ID        string
	Kind      NodeKind
	Name      string
	Namespace string
	Label     string
	Props     map[string]string
}

type Edge struct {
	From   string
	To     string
	Kind   string
	Reason string
	Weight int
}

type Graph struct {
	Nodes map[string]Node
	Edges []Edge
}

type SearchOptions struct {
	StartID   string
	Goal      string
	Namespace string
	Top       int
}

type ScenarioRecommendation struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type AttackPath struct {
	Start     string                   `json:"start"`
	Goal      string                   `json:"goal"`
	Score     int                      `json:"score"`
	Edges     []Edge                   `json:"edges"`
	Scenarios []ScenarioRecommendation `json:"scenarios,omitempty"`
}
