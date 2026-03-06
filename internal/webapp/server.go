package webapp

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"

	"k8s-security-lab/internal/attackgraph"
)

//go:embed static
var staticFS embed.FS

type diffRequest struct {
	Before    attackgraph.GraphPayload  `json:"before"`
	After     *attackgraph.GraphPayload `json:"after,omitempty"`
	StartID   string                    `json:"from"`
	Namespace string                    `json:"namespace"`
}

func NewServer() (http.Handler, error) {
	mux := http.NewServeMux()

	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	mux.Handle("/api/healthz", withJSONHeaders(http.HandlerFunc(handleHealthz)))
	mux.Handle("/api/graph", withJSONHeaders(http.HandlerFunc(handleGraph)))
	mux.Handle("/api/paths", withJSONHeaders(http.HandlerFunc(handlePaths)))
	mux.Handle("/api/explain", withJSONHeaders(http.HandlerFunc(handleExplain)))
	mux.Handle("/api/diff", withJSONHeaders(http.HandlerFunc(handleDiff)))
	mux.Handle("/", http.FileServer(http.FS(staticRoot)))

	return mux, nil
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := attackgraph.Build(context.Background())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	payload := attackgraph.GraphPayloadFromGraph(
		graph,
		parseStartRef(r),
		r.URL.Query().Get("namespace"),
	)

	writeJSON(w, http.StatusOK, payload)
}

func handlePaths(w http.ResponseWriter, r *http.Request) {
	graph, err := attackgraph.Build(context.Background())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	paths, err := attackgraph.FindAttackPaths(graph, attackgraph.SearchOptions{
		StartID:   parseStartRef(r),
		Goal:      r.URL.Query().Get("goal"),
		Namespace: r.URL.Query().Get("namespace"),
		Top:       parsePositiveInt(r, "top"),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	output, err := attackgraph.RenderPathsJSON(paths, graph)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeRawJSON(w, http.StatusOK, output)
}

func handleExplain(w http.ResponseWriter, r *http.Request) {
	graph, err := attackgraph.Build(context.Background())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	top := parsePositiveInt(r, "top")
	if top == 0 {
		top = 1
	}

	paths, err := attackgraph.FindAttackPaths(graph, attackgraph.SearchOptions{
		StartID:   parseStartRef(r),
		Goal:      r.URL.Query().Get("goal"),
		Namespace: r.URL.Query().Get("namespace"),
		Top:       top,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	output, err := attackgraph.RenderExplainJSON(paths, graph)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeRawJSON(w, http.StatusOK, output)
}

func handleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	var request diffRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	startID := request.StartID
	if startID == "" {
		startID = "sa:tenant-a/tenant-sa"
	}

	beforeGraph := attackgraph.GraphFromPayload(request.Before)

	var afterGraph *attackgraph.Graph
	if request.After != nil {
		afterGraph = attackgraph.GraphFromPayload(*request.After)
	} else {
		var err error
		afterGraph, err = attackgraph.Build(context.Background())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}

	beforeNodes, beforeEdges := beforeGraph.Filtered(startID, request.Namespace)
	afterNodes, afterEdges := afterGraph.Filtered(startID, request.Namespace)

	diff := attackgraph.DiffGraphs(
		&attackgraph.Graph{Nodes: beforeNodes, Edges: beforeEdges},
		&attackgraph.Graph{Nodes: afterNodes, Edges: afterEdges},
	)

	output, err := attackgraph.RenderDiffJSON(diff)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeRawJSON(w, http.StatusOK, output)
}

func parseStartRef(r *http.Request) string {
	start := r.URL.Query().Get("from")
	if start == "" {
		return "sa:tenant-a/tenant-sa"
	}
	return attackgraph.ParseNodeReference(start)
}

func parsePositiveInt(r *http.Request, name string) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0
	}

	return value
}

func withJSONHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeRawJSON(w http.ResponseWriter, status int, payload string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(payload))
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{
		"error": err.Error(),
	})
}
