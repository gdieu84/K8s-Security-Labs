package commands

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"k8s-security-lab/internal/attackgraph"
	"k8s-security-lab/internal/webapp"
)

func GraphCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing graph subcommand")
	}

	switch args[0] {
	case "paths":
		return graphPathsCommand(args[1:])
	case "explain":
		return graphExplainCommand(args[1:])
	case "export":
		return graphExportCommand(args[1:])
	case "diff":
		return graphDiffCommand(args[1:])
	case "serve":
		return graphServeCommand(args[1:])
	default:
		return fmt.Errorf("unknown graph subcommand: %s", args[0])
	}
}

func graphServeCommand(args []string) error {
	addr := "127.0.0.1:8080"

	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--addr":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --addr")
			}
			addr = args[index]
		default:
			return fmt.Errorf("unknown graph serve flag: %s", args[index])
		}
	}

	handler, err := webapp.NewServer()
	if err != nil {
		return err
	}

	fmt.Printf("Serving attack graph UI on http://%s\n", addr)
	return http.ListenAndServe(addr, handler)
}

func graphExplainCommand(args []string) error {
	startRef := "sa:tenant-a/tenant-sa"
	goal := ""
	format := "text"
	namespace := ""
	top := 1

	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--from":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --from")
			}
			startRef = attackgraph.ParseNodeReference(args[index])
		case "--goal":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --goal")
			}
			goal = args[index]
		case "--format":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --format")
			}
			format = args[index]
		case "--namespace":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --namespace")
			}
			namespace = args[index]
		case "--top":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --top")
			}
			value, err := strconv.Atoi(args[index])
			if err != nil || value < 1 {
				return fmt.Errorf("invalid value for --top: %s", args[index])
			}
			top = value
		default:
			return fmt.Errorf("unknown graph explain flag: %s", args[index])
		}
	}

	graph, err := attackgraph.Build(context.Background())
	if err != nil {
		return err
	}

	paths, err := attackgraph.FindAttackPaths(graph, attackgraph.SearchOptions{
		StartID:   startRef,
		Goal:      goal,
		Namespace: namespace,
		Top:       top,
	})
	if err != nil {
		return err
	}

	switch format {
	case "text":
		fmt.Println(attackgraph.RenderExplain(paths, graph))
		return nil
	case "json":
		output, renderErr := attackgraph.RenderExplainJSON(paths, graph)
		if renderErr != nil {
			return renderErr
		}
		fmt.Println(output)
		return nil
	default:
		return fmt.Errorf("unsupported graph explain format: %s", format)
	}
}

func graphPathsCommand(args []string) error {
	startRef := "sa:tenant-a/tenant-sa"
	goal := ""
	format := "text"
	namespace := ""
	top := 0

	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--from":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --from")
			}
			startRef = attackgraph.ParseNodeReference(args[index])
		case "--goal":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --goal")
			}
			goal = args[index]
		case "--format":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --format")
			}
			format = args[index]
		case "--namespace":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --namespace")
			}
			namespace = args[index]
		case "--top":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --top")
			}
			value, err := strconv.Atoi(args[index])
			if err != nil || value < 1 {
				return fmt.Errorf("invalid value for --top: %s", args[index])
			}
			top = value
		default:
			return fmt.Errorf("unknown graph paths flag: %s", args[index])
		}
	}

	graph, err := attackgraph.Build(context.Background())
	if err != nil {
		return err
	}

	paths, err := attackgraph.FindAttackPaths(graph, attackgraph.SearchOptions{
		StartID:   startRef,
		Goal:      goal,
		Namespace: namespace,
		Top:       top,
	})
	if err != nil {
		return err
	}

	switch format {
	case "text":
		fmt.Println(attackgraph.RenderPaths(paths, graph))
		return nil
	case "json":
		output, renderErr := attackgraph.RenderPathsJSON(paths, graph)
		if renderErr != nil {
			return renderErr
		}
		fmt.Println(output)
		return nil
	default:
		return fmt.Errorf("unsupported graph paths format: %s", format)
	}
}

func graphExportCommand(args []string) error {
	format := "mermaid"
	startRef := "sa:tenant-a/tenant-sa"
	namespace := ""

	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--format":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --format")
			}
			format = args[index]
		case "--from":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --from")
			}
			startRef = attackgraph.ParseNodeReference(args[index])
		case "--namespace":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --namespace")
			}
			namespace = args[index]
		default:
			return fmt.Errorf("unknown graph export flag: %s", args[index])
		}
	}

	graph, err := attackgraph.Build(context.Background())
	if err != nil {
		return err
	}

	switch format {
	case "mermaid":
		nodes, edges := graph.Filtered(startRef, namespace)
		fmt.Println(attackgraph.RenderMermaid(&attackgraph.Graph{Nodes: nodes, Edges: edges}, ""))
		return nil
	case "dot":
		nodes, edges := graph.Filtered(startRef, namespace)
		fmt.Println(attackgraph.RenderDOT(&attackgraph.Graph{Nodes: nodes, Edges: edges}, ""))
		return nil
	case "json":
		output, renderErr := attackgraph.RenderGraphJSON(graph, startRef, namespace)
		if renderErr != nil {
			return renderErr
		}
		fmt.Println(output)
		return nil
	default:
		return fmt.Errorf("unsupported graph export format: %s", format)
	}
}

func graphDiffCommand(args []string) error {
	beforePath := ""
	afterPath := ""
	startRef := "sa:tenant-a/tenant-sa"
	namespace := ""
	format := "text"

	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--before":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --before")
			}
			beforePath = args[index]
		case "--after":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --after")
			}
			afterPath = args[index]
		case "--from":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --from")
			}
			startRef = attackgraph.ParseNodeReference(args[index])
		case "--namespace":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --namespace")
			}
			namespace = args[index]
		case "--format":
			index++
			if index >= len(args) {
				return fmt.Errorf("missing value for --format")
			}
			format = args[index]
		default:
			return fmt.Errorf("unknown graph diff flag: %s", args[index])
		}
	}

	if beforePath == "" {
		return fmt.Errorf("missing required --before snapshot path")
	}

	beforeGraph, err := attackgraph.LoadGraphJSON(beforePath)
	if err != nil {
		return err
	}

	var afterGraph *attackgraph.Graph
	if afterPath != "" {
		afterGraph, err = attackgraph.LoadGraphJSON(afterPath)
		if err != nil {
			return err
		}
	} else {
		afterGraph, err = attackgraph.Build(context.Background())
		if err != nil {
			return err
		}
	}

	beforeNodes, beforeEdges := beforeGraph.Filtered(startRef, namespace)
	afterNodes, afterEdges := afterGraph.Filtered(startRef, namespace)

	diff := attackgraph.DiffGraphs(
		&attackgraph.Graph{Nodes: beforeNodes, Edges: beforeEdges},
		&attackgraph.Graph{Nodes: afterNodes, Edges: afterEdges},
	)

	switch format {
	case "text":
		fmt.Println(attackgraph.RenderDiff(diff))
		return nil
	case "json":
		output, renderErr := attackgraph.RenderDiffJSON(diff)
		if renderErr != nil {
			return renderErr
		}
		fmt.Println(output)
		return nil
	default:
		return fmt.Errorf("unsupported graph diff format: %s", format)
	}
}
