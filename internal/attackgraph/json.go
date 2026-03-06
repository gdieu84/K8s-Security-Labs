package attackgraph

import "encoding/json"

type GraphPayload struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func GraphPayloadFromGraph(graph *Graph, startID, namespace string) GraphPayload {
	nodes, edges := graph.Filtered(startID, namespace)

	orderedNodes := make([]Node, 0, len(nodes))
	for _, id := range sortedNodeIDs(nodes) {
		orderedNodes = append(orderedNodes, nodes[id])
	}

	sortEdges(edges)

	return GraphPayload{
		Nodes: orderedNodes,
		Edges: edges,
	}
}

func GraphFromPayload(payload GraphPayload) *Graph {
	graph := NewGraph()
	for _, node := range payload.Nodes {
		graph.AddNode(node)
	}
	for _, edge := range payload.Edges {
		graph.AddEdge(edge)
	}
	return graph
}

func GraphPayloadFromJSON(data []byte) (GraphPayload, error) {
	var payload GraphPayload
	err := json.Unmarshal(data, &payload)
	return payload, err
}
