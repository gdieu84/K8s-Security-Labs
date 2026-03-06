package attackgraph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func RenderPaths(paths []AttackPath, graph *Graph) string {
	if len(paths) == 0 {
		return "No attack paths found."
	}

	var builder strings.Builder

	for index, path := range paths {
		startLabel := graph.NodeLabel(path.Start)
		goalLabel := graph.NodeLabel(path.Goal)

		builder.WriteString(fmt.Sprintf("Start: %s\n", startLabel))
		builder.WriteString(fmt.Sprintf("Goal: %s\n", goalLabel))
		builder.WriteString(fmt.Sprintf("Score: %d\n", path.Score))
		builder.WriteString("\n")

		for stepIndex, edge := range path.Edges {
			builder.WriteString(fmt.Sprintf(
				"%d. %s -> %s\n",
				stepIndex+1,
				graph.NodeLabel(edge.To),
				edge.Reason,
			))
		}

		if len(path.Scenarios) > 0 {
			builder.WriteString("\nRelated lab scenarios:\n")
			for _, scenario := range path.Scenarios {
				builder.WriteString(fmt.Sprintf("- %s: %s\n", scenario.Command, scenario.Reason))
			}
		}

		if index != len(paths)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

func RenderPathsJSON(paths []AttackPath, graph *Graph) (string, error) {
	type pathStep struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Kind   string `json:"kind"`
		Reason string `json:"reason"`
	}

	type pathPayload struct {
		Start      string     `json:"start"`
		StartLabel string     `json:"start_label"`
		Goal       string     `json:"goal"`
		GoalLabel  string     `json:"goal_label"`
		Score      int        `json:"score"`
		Steps      []pathStep `json:"steps"`
	}

	payload := make([]pathPayload, 0, len(paths))
	for _, path := range paths {
		steps := make([]pathStep, 0, len(path.Edges))
		for _, edge := range path.Edges {
			steps = append(steps, pathStep{
				From:   edge.From,
				To:     edge.To,
				Kind:   edge.Kind,
				Reason: edge.Reason,
			})
		}

		payload = append(payload, pathPayload{
			Start:      path.Start,
			StartLabel: graph.NodeLabel(path.Start),
			Goal:       path.Goal,
			GoalLabel:  graph.NodeLabel(path.Goal),
			Score:      path.Score,
			Steps:      steps,
		})
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func RenderExplain(paths []AttackPath, graph *Graph) string {
	if len(paths) == 0 {
		return "No explanation available because no matching attack path was found."
	}

	var builder strings.Builder

	for index, path := range paths {
		builder.WriteString(fmt.Sprintf("Start: %s\n", graph.NodeLabel(path.Start)))
		builder.WriteString(fmt.Sprintf("Goal: %s\n", graph.NodeLabel(path.Goal)))
		builder.WriteString(fmt.Sprintf("Why reachable: %d-step path with score %d\n", len(path.Edges), path.Score))
		builder.WriteString("\n")

		for stepIndex, edge := range path.Edges {
			builder.WriteString(fmt.Sprintf(
				"%d. %s -> %s\n",
				stepIndex+1,
				graph.NodeLabel(edge.From),
				graph.NodeLabel(edge.To),
			))
			builder.WriteString(fmt.Sprintf("   Edge: %s\n", edge.Kind))
			builder.WriteString(fmt.Sprintf("   Why: %s\n", edge.Reason))
		}

		if len(path.Scenarios) > 0 {
			builder.WriteString("\nBest matching lab scenarios:\n")
			for _, scenario := range path.Scenarios {
				builder.WriteString(fmt.Sprintf("- %s: %s\n", scenario.Command, scenario.Reason))
			}
		}

		if index != len(paths)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

func RenderExplainJSON(paths []AttackPath, graph *Graph) (string, error) {
	type explanationStep struct {
		From      string `json:"from"`
		FromLabel string `json:"from_label"`
		To        string `json:"to"`
		ToLabel   string `json:"to_label"`
		Kind      string `json:"kind"`
		Why       string `json:"why"`
	}

	type explanationPayload struct {
		Start      string                   `json:"start"`
		StartLabel string                   `json:"start_label"`
		Goal       string                   `json:"goal"`
		GoalLabel  string                   `json:"goal_label"`
		Score      int                      `json:"score"`
		Scenarios  []ScenarioRecommendation `json:"scenarios,omitempty"`
		Steps      []explanationStep        `json:"steps"`
	}

	payload := make([]explanationPayload, 0, len(paths))
	for _, path := range paths {
		steps := make([]explanationStep, 0, len(path.Edges))
		for _, edge := range path.Edges {
			steps = append(steps, explanationStep{
				From:      edge.From,
				FromLabel: graph.NodeLabel(edge.From),
				To:        edge.To,
				ToLabel:   graph.NodeLabel(edge.To),
				Kind:      edge.Kind,
				Why:       edge.Reason,
			})
		}

		payload = append(payload, explanationPayload{
			Start:      path.Start,
			StartLabel: graph.NodeLabel(path.Start),
			Goal:       path.Goal,
			GoalLabel:  graph.NodeLabel(path.Goal),
			Score:      path.Score,
			Scenarios:  path.Scenarios,
			Steps:      steps,
		})
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func RenderMermaid(graph *Graph, startID string) string {
	nodes, edges := filterGraph(graph, startID)

	var builder strings.Builder
	builder.WriteString("flowchart TD\n")

	for _, id := range sortedNodeIDs(nodes) {
		node := nodes[id]
		builder.WriteString(fmt.Sprintf(
			"    %s[\"%s\"]\n",
			sanitizeMermaidID(id),
			escapeMermaidLabel(node.Label),
		))
	}

	sortEdges(edges)

	for _, edge := range edges {
		builder.WriteString(fmt.Sprintf(
			"    %s -->|%s| %s\n",
			sanitizeMermaidID(edge.From),
			escapeMermaidLabel(edge.Kind),
			sanitizeMermaidID(edge.To),
		))
	}

	return builder.String()
}

func RenderDOT(graph *Graph, startID string) string {
	nodes, edges := filterGraph(graph, startID)

	var builder strings.Builder
	builder.WriteString("digraph AttackGraph {\n")
	builder.WriteString("    rankdir=LR;\n")
	builder.WriteString("    node [shape=box];\n")

	for _, id := range sortedNodeIDs(nodes) {
		node := nodes[id]
		builder.WriteString(fmt.Sprintf(
			"    \"%s\" [label=\"%s\"];\n",
			escapeDOTLabel(id),
			escapeDOTLabel(node.Label),
		))
	}

	sortEdges(edges)

	for _, edge := range edges {
		builder.WriteString(fmt.Sprintf(
			"    \"%s\" -> \"%s\" [label=\"%s\"];\n",
			escapeDOTLabel(edge.From),
			escapeDOTLabel(edge.To),
			escapeDOTLabel(edge.Kind),
		))
	}

	builder.WriteString("}\n")

	return builder.String()
}

func RenderGraphJSON(graph *Graph, startID, namespace string) (string, error) {
	nodes, edges := graph.Filtered(startID, namespace)

	type graphPayload struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	}

	orderedNodes := make([]Node, 0, len(nodes))
	for _, id := range sortedNodeIDs(nodes) {
		orderedNodes = append(orderedNodes, nodes[id])
	}

	sortEdges(edges)

	data, err := json.MarshalIndent(graphPayload{
		Nodes: orderedNodes,
		Edges: edges,
	}, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func escapeMermaidLabel(label string) string {
	return strings.ReplaceAll(label, "\"", "\\\"")
}

func escapeDOTLabel(label string) string {
	return strings.ReplaceAll(label, "\"", "\\\"")
}

func filterGraph(graph *Graph, startID string) (map[string]Node, []Edge) {
	return graph.Filtered(startID, "")
}

func sortEdges(edges []Edge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From == edges[j].From {
			if edges[i].To == edges[j].To {
				return edges[i].Kind < edges[j].Kind
			}
			return edges[i].To < edges[j].To
		}
		return edges[i].From < edges[j].From
	})
}
