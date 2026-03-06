package attackgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type GraphDiff struct {
	AddedNodes   []Node `json:"added_nodes"`
	RemovedNodes []Node `json:"removed_nodes"`
	AddedEdges   []Edge `json:"added_edges"`
	RemovedEdges []Edge `json:"removed_edges"`
}

func LoadGraphJSON(path string) (*Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	payload, err := GraphPayloadFromJSON(data)
	if err != nil {
		return nil, err
	}

	return GraphFromPayload(payload), nil
}

func DiffGraphs(before, after *Graph) GraphDiff {
	diff := GraphDiff{
		AddedNodes:   []Node{},
		RemovedNodes: []Node{},
		AddedEdges:   []Edge{},
		RemovedEdges: []Edge{},
	}

	for _, id := range sortedNodeIDs(after.Nodes) {
		if _, exists := before.Nodes[id]; !exists {
			diff.AddedNodes = append(diff.AddedNodes, after.Nodes[id])
		}
	}

	for _, id := range sortedNodeIDs(before.Nodes) {
		if _, exists := after.Nodes[id]; !exists {
			diff.RemovedNodes = append(diff.RemovedNodes, before.Nodes[id])
		}
	}

	beforeEdges := edgeIndex(before.Edges)
	afterEdges := edgeIndex(after.Edges)

	for _, key := range sortedEdgeKeys(afterEdges) {
		if _, exists := beforeEdges[key]; !exists {
			diff.AddedEdges = append(diff.AddedEdges, afterEdges[key])
		}
	}

	for _, key := range sortedEdgeKeys(beforeEdges) {
		if _, exists := afterEdges[key]; !exists {
			diff.RemovedEdges = append(diff.RemovedEdges, beforeEdges[key])
		}
	}

	return diff
}

func RenderDiff(diff GraphDiff) string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("Added nodes: %d\n", len(diff.AddedNodes)))
	for _, node := range diff.AddedNodes {
		builder.WriteString(fmt.Sprintf("- %s\n", diffNodeLabel(node)))
	}

	builder.WriteString(fmt.Sprintf("\nRemoved nodes: %d\n", len(diff.RemovedNodes)))
	for _, node := range diff.RemovedNodes {
		builder.WriteString(fmt.Sprintf("- %s\n", diffNodeLabel(node)))
	}

	builder.WriteString(fmt.Sprintf("\nAdded edges: %d\n", len(diff.AddedEdges)))
	for _, edge := range diff.AddedEdges {
		builder.WriteString(fmt.Sprintf("- %s -> %s [%s]\n", edge.From, edge.To, edge.Kind))
	}

	builder.WriteString(fmt.Sprintf("\nRemoved edges: %d\n", len(diff.RemovedEdges)))
	for _, edge := range diff.RemovedEdges {
		builder.WriteString(fmt.Sprintf("- %s -> %s [%s]\n", edge.From, edge.To, edge.Kind))
	}

	return builder.String()
}

func RenderDiffJSON(diff GraphDiff) (string, error) {
	data, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func edgeIndex(edges []Edge) map[string]Edge {
	index := make(map[string]Edge)
	for _, edge := range edges {
		index[edgeKey(edge)] = edge
	}
	return index
}

func edgeKey(edge Edge) string {
	return edge.From + "|" + edge.To + "|" + edge.Kind + "|" + edge.Reason
}

func sortedEdgeKeys(index map[string]Edge) []string {
	keys := make([]string, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func diffNodeLabel(node Node) string {
	if node.Namespace == "" {
		return string(node.Kind) + " " + node.Name
	}
	return string(node.Kind) + " " + node.Namespace + "/" + node.Name
}
