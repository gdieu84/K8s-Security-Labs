package attackgraph

import (
	"fmt"
	"sort"
	"strings"
)

func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]Node),
		Edges: make([]Edge, 0),
	}
}

func (g *Graph) AddNode(node Node) {
	if node.Label == "" {
		node.Label = node.Name
	}
	if node.Props == nil {
		node.Props = map[string]string{}
	}
	g.Nodes[node.ID] = node
}

func (g *Graph) AddEdge(edge Edge) {
	if edge.Weight == 0 {
		edge.Weight = 1
	}
	g.Edges = append(g.Edges, edge)
}

func (g *Graph) Outgoing(nodeID string) []Edge {
	out := make([]Edge, 0)
	for _, edge := range g.Edges {
		if edge.From == nodeID {
			out = append(out, edge)
		}
	}
	return out
}

func (g *Graph) Reachable(startID string) map[string]bool {
	reachable := map[string]bool{}
	queue := []string{startID}
	reachable[startID] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, edge := range g.Outgoing(current) {
			if reachable[edge.To] {
				continue
			}

			reachable[edge.To] = true
			queue = append(queue, edge.To)
		}
	}

	return reachable
}

func (g *Graph) Filtered(startID, namespace string) (map[string]Node, []Edge) {
	nodes := g.Nodes
	edges := g.Edges

	if startID != "" {
		reachable := g.Reachable(startID)
		filteredNodes := make(map[string]Node)
		filteredEdges := make([]Edge, 0)

		for id, node := range g.Nodes {
			if reachable[id] {
				filteredNodes[id] = node
			}
		}

		for _, edge := range g.Edges {
			if reachable[edge.From] && reachable[edge.To] {
				filteredEdges = append(filteredEdges, edge)
			}
		}

		nodes = filteredNodes
		edges = filteredEdges
	}

	if namespace == "" {
		return nodes, edges
	}

	namespaceNodes := make(map[string]Node)
	for id, node := range nodes {
		if nodeMatchesNamespace(node, namespace) || id == startID {
			namespaceNodes[id] = node
		}
	}

	namespaceEdges := make([]Edge, 0)
	for _, edge := range edges {
		if _, fromOK := namespaceNodes[edge.From]; !fromOK {
			continue
		}
		if _, toOK := namespaceNodes[edge.To]; !toOK {
			continue
		}
		namespaceEdges = append(namespaceEdges, edge)
	}

	return namespaceNodes, namespaceEdges
}

func (g *Graph) NodeLabel(id string) string {
	node, exists := g.Nodes[id]
	if !exists {
		return id
	}

	if node.Namespace == "" {
		return fmt.Sprintf("%s %s", node.Kind, node.Name)
	}

	return fmt.Sprintf("%s %s/%s", node.Kind, node.Namespace, node.Name)
}

func sortedNodeIDs(nodes map[string]Node) []string {
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	return ids
}

func sanitizeMermaidID(id string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"-", "_",
		".", "_",
		"*", "star",
	)

	return replacer.Replace(id)
}

func nodeMatchesNamespace(node Node, namespace string) bool {
	if node.Namespace == namespace {
		return true
	}

	if node.Namespace == "" {
		scope := node.Props["scope"]
		if scope == "" || scope == "cluster" || scope == "all-namespaces" {
			return true
		}
		return scope == namespace
	}

	return false
}
