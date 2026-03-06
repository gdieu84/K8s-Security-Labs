package attackgraph

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var goalAliases = map[string]string{
	"admin":            "namespace-admin-equivalent",
	"config":           "config-integrity-compromise",
	"configmap-poison": "config-integrity-compromise",
	"exec":             "workload-command-execution",
	"node":             "node-compromise",
	"namespace-admin":  "namespace-admin-equivalent",
	"persistence":      "persistence",
	"secret":           "secret-exposure",
	"secrets":          "secret-exposure",
	"token":            "fresh-serviceaccount-token",
	"workload-exec":    "workload-command-execution",
}

var capabilityScoreBoosts = map[string]int{
	"bind-powerful-role":             16,
	"create-arbitrary-pod":           18,
	"create-privileged-hostpath-pod": 20,
	"establish-persistence":          12,
	"exec-into-existing-pod":         15,
	"harvest-workload-secrets":       12,
	"mint-serviceaccount-token":      8,
	"modify-workload-behavior":       10,
}

func FindAttackPaths(graph *Graph, options SearchOptions) ([]AttackPath, error) {
	if options.StartID == "" {
		return nil, fmt.Errorf("missing start node")
	}
	if _, exists := graph.Nodes[options.StartID]; !exists {
		return nil, fmt.Errorf("unknown start node: %s", options.StartID)
	}

	nodes, edges := graph.Filtered(options.StartID, options.Namespace)
	if _, exists := nodes[options.StartID]; !exists {
		return nil, fmt.Errorf("start node %s is not visible in namespace filter %s", options.StartID, options.Namespace)
	}

	goalFilter := normalizeGoal(options.Goal)
	adjacency := outgoingEdges(edges)

	type predecessor struct {
		From string
		Edge Edge
	}

	queue := []string{options.StartID}
	visited := map[string]bool{options.StartID: true}
	prev := map[string]predecessor{}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, edge := range adjacency[current] {
			if visited[edge.To] {
				continue
			}

			visited[edge.To] = true
			prev[edge.To] = predecessor{
				From: current,
				Edge: edge,
			}
			queue = append(queue, edge.To)
		}
	}

	paths := make([]AttackPath, 0)

	for nodeID, node := range nodes {
		if node.Kind != NodeKindImpact {
			continue
		}
		if goalFilter != "" && node.Name != goalFilter && nodeID != goalFilter {
			continue
		}
		if !visited[nodeID] {
			continue
		}

		pathEdges := make([]Edge, 0)
		current := nodeID
		for current != options.StartID {
			step, exists := prev[current]
			if !exists {
				break
			}
			pathEdges = append([]Edge{step.Edge}, pathEdges...)
			current = step.From
		}

		score := pathScore(nodes, pathEdges, nodeID)
		path := AttackPath{
			Start: options.StartID,
			Goal:  nodeID,
			Score: score,
			Edges: pathEdges,
		}
		path.Scenarios = RecommendScenarios(path, &Graph{Nodes: nodes, Edges: edges})
		paths = append(paths, path)
	}

	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Score == paths[j].Score {
			if len(paths[i].Edges) == len(paths[j].Edges) {
				return paths[i].Goal < paths[j].Goal
			}
			return len(paths[i].Edges) < len(paths[j].Edges)
		}
		return paths[i].Score > paths[j].Score
	})

	if options.Top > 0 && len(paths) > options.Top {
		paths = paths[:options.Top]
	}

	return paths, nil
}

func outgoingEdges(edges []Edge) map[string][]Edge {
	adjacency := make(map[string][]Edge)
	for _, edge := range edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge)
	}
	return adjacency
}

func normalizeGoal(goal string) string {
	goal = strings.TrimSpace(strings.ToLower(goal))
	if goal == "" {
		return ""
	}
	if alias, exists := goalAliases[goal]; exists {
		return alias
	}
	return goal
}

func pathScore(nodes map[string]Node, pathEdges []Edge, goalID string) int {
	node := nodes[goalID]
	severity := 50
	if rawSeverity, exists := node.Props["severity"]; exists {
		if parsed, err := strconv.Atoi(rawSeverity); err == nil {
			severity = parsed
		}
	}

	score := severity - len(pathEdges)*2

	for _, edge := range pathEdges {
		target := nodes[edge.To]
		if target.Kind == NodeKindCapability {
			score += capabilityScoreBoosts[target.Name]
		}

		switch edge.Kind {
		case "CAN_ACCESS":
			score += 2
		case "IMPACTS":
			score += 3
		case "DERIVES":
			score += 1
		}
	}

	return score
}
