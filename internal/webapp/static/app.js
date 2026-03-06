const state = {
  graph: null,
  paths: [],
  explanations: [],
  diff: null,
  selectedNodeId: null,
  selectedEdgeKey: null,
  activePathIndex: -1,
  zoom: 1,
};

const palette = {
  Pod: { fill: '#d7ebee', stroke: '#246a73' },
  ServiceAccount: { fill: '#d3ece7', stroke: '#0f766e' },
  Role: { fill: '#dde5ef', stroke: '#475569' },
  ClusterRole: { fill: '#dde5ef', stroke: '#475569' },
  RoleBinding: { fill: '#dde5ef', stroke: '#475569' },
  ClusterRoleBinding: { fill: '#dde5ef', stroke: '#475569' },
  Permission: { fill: '#e5e7eb', stroke: '#6b7280' },
  Capability: { fill: '#f6e3b7', stroke: '#c58a11' },
  Secret: { fill: '#f0d5df', stroke: '#8f2d56' },
  ConfigMap: { fill: '#e4e9cf', stroke: '#687433' },
  CronJob: { fill: '#f3dcc1', stroke: '#8d5a1b' },
  Impact: { fill: '#f2d3d0', stroke: '#a63d40' },
  default: { fill: '#efe4d1', stroke: '#5e655c' },
};

const columns = ['Pod', 'ServiceAccount', 'RoleBinding', 'Role', 'ClusterRoleBinding', 'ClusterRole', 'Permission', 'Capability', 'Secret', 'ConfigMap', 'CronJob', 'Impact'];

const els = {
  startRef: document.getElementById('startRef'),
  namespace: document.getElementById('namespace'),
  goal: document.getElementById('goal'),
  top: document.getElementById('top'),
  status: document.getElementById('status'),
  graphSvg: document.getElementById('graphSvg'),
  graphStats: document.getElementById('graphStats'),
  selectedDetails: document.getElementById('selectedDetails'),
  pathsList: document.getElementById('pathsList'),
  explainOutput: document.getElementById('explainOutput'),
  scenarioList: document.getElementById('scenarioList'),
  diffOutput: document.getElementById('diffOutput'),
  beforeFile: document.getElementById('beforeFile'),
  loadGraphBtn: document.getElementById('loadGraphBtn'),
  loadPathsBtn: document.getElementById('loadPathsBtn'),
  explainBtn: document.getElementById('explainBtn'),
  downloadBtn: document.getElementById('downloadBtn'),
  diffBtn: document.getElementById('diffBtn'),
  zoomOutBtn: document.getElementById('zoomOutBtn'),
  zoomResetBtn: document.getElementById('zoomResetBtn'),
  zoomInBtn: document.getElementById('zoomInBtn'),
};

function apiQuery(extra = {}) {
  const params = new URLSearchParams();
  const startRef = els.startRef.value.trim();
  const namespace = els.namespace.value.trim();
  const goal = els.goal.value.trim();
  const top = els.top.value.trim();

  if (startRef) params.set('from', startRef);
  if (namespace) params.set('namespace', namespace);
  if (goal) params.set('goal', goal);
  if (top) params.set('top', top);

  Object.entries(extra).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, value);
    }
  });

  return params.toString();
}

async function fetchJSON(path, options) {
  const response = await fetch(path, options);
  let data;
  try {
    data = await response.json();
  } catch (error) {
    throw new Error(`invalid JSON from ${path}`);
  }
  if (!response.ok) {
    throw new Error(data.error || `request failed: ${response.status}`);
  }
  return data;
}

function setStatus(message, muted = false) {
  els.status.textContent = message;
  els.status.className = muted ? 'status-muted' : '';
}

function edgeKey(edge) {
  return `${edge.from || edge.From}->${edge.to || edge.To}:${edge.kind || edge.Kind}`;
}

function graphEdgeKey(edge) {
  return `${edge.From}->${edge.To}:${edge.Kind}`;
}

function getNode(id) {
  if (!state.graph) {
    return null;
  }
  return state.graph.nodes.find((node) => node.ID === id) || null;
}

function prettyJSON(value) {
  return JSON.stringify(value, null, 2);
}

function nodeColor(kind) {
  return palette[kind] || palette.default;
}

function nodeLabelLines(node) {
  const title = node.Label || node.Name || node.ID;
  if (title.length <= 26) {
    return [title];
  }

  const words = title.split(' ');
  const lines = [];
  let current = '';

  words.forEach((word) => {
    const next = current ? `${current} ${word}` : word;
    if (next.length > 26 && current) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  });

  if (current) {
    lines.push(current);
  }

  return lines.slice(0, 3);
}

function clampZoom(nextZoom) {
  return Math.max(0.6, Math.min(2.4, Number(nextZoom.toFixed(2))));
}

function updateZoomLabel() {
  els.zoomResetBtn.textContent = `${Math.round(state.zoom * 100)}%`;
}

function setZoom(nextZoom) {
  state.zoom = clampZoom(nextZoom);
  updateZoomLabel();
  if (state.graph) {
    renderGraph();
  }
}

function layoutGraph(graph) {
  const width = Math.max(1200, els.graphSvg.parentElement.clientWidth || 1200);
  const kindBuckets = new Map();
  columns.forEach((kind) => kindBuckets.set(kind, []));
  const extras = [];

  graph.nodes.forEach((node) => {
    if (kindBuckets.has(node.Kind)) {
      kindBuckets.get(node.Kind).push(node);
    } else {
      extras.push(node);
    }
  });

  const orderedKinds = columns.filter((kind) => kindBuckets.get(kind).length > 0);
  if (extras.length > 0) {
    orderedKinds.push('Other');
    kindBuckets.set('Other', extras);
  }

  const positions = new Map();
  const columnWidth = 220;
  const nodeHeight = 80;
  const rowGap = 28;
  const leftPadding = 72;
  const topPadding = 96;

  let maxRows = 1;
  orderedKinds.forEach((kind, columnIndex) => {
    const nodes = kindBuckets.get(kind) || [];
    nodes.sort((a, b) => a.ID.localeCompare(b.ID));
    maxRows = Math.max(maxRows, nodes.length);
    nodes.forEach((node, index) => {
      positions.set(node.ID, {
        x: leftPadding + columnIndex * columnWidth,
        y: topPadding + index * (nodeHeight + rowGap),
        width: 164,
        height: nodeHeight,
      });
    });
  });

  const height = Math.max(720, topPadding + maxRows * (nodeHeight + rowGap) + 84);
  return {
    width: leftPadding + Math.max(orderedKinds.length, 1) * columnWidth + 100,
    height,
    positions,
    orderedKinds,
  };
}

function createSvg(tag, attrs = {}) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, value));
  return el;
}

function updateStats() {
  const badges = [];
  const nodeCount = state.graph ? state.graph.nodes.length : 0;
  const edgeCount = state.graph ? state.graph.edges.length : 0;
  badges.push(`<span class="badge">Nodes ${nodeCount}</span>`);
  badges.push(`<span class="badge">Edges ${edgeCount}</span>`);
  if (state.paths.length) {
    badges.push(`<span class="badge">Paths ${state.paths.length}</span>`);
  }
  if (state.activePathIndex >= 0 && state.paths[state.activePathIndex]) {
    badges.push(`<span class="badge">Active score ${state.paths[state.activePathIndex].score}</span>`);
  }
  els.graphStats.innerHTML = badges.join('');
}

function renderGraph() {
  const svg = els.graphSvg;
  svg.innerHTML = '';
  updateStats();

  if (!state.graph || state.graph.nodes.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'graph-empty';
    empty.textContent = 'No graph loaded.';
    const parent = svg.parentElement;
    const existing = parent.querySelector('.graph-empty');
    if (existing) {
      existing.remove();
    }
    parent.appendChild(empty);
    return;
  }

  const parent = svg.parentElement;
  const existingEmpty = parent.querySelector('.graph-empty');
  if (existingEmpty) {
    existingEmpty.remove();
  }

  const { width, height, positions, orderedKinds } = layoutGraph(state.graph);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('width', String(Math.round(width * state.zoom)));
  svg.setAttribute('height', String(Math.round(height * state.zoom)));

  const defs = createSvg('defs');
  const marker = createSvg('marker', {
    id: 'edge-arrow',
    markerWidth: '10',
    markerHeight: '10',
    refX: '8',
    refY: '3',
    orient: 'auto',
    markerUnits: 'strokeWidth',
  });
  marker.appendChild(createSvg('path', { d: 'M0,0 L0,6 L9,3 z', fill: 'rgba(238, 244, 235, 0.45)' }));
  defs.appendChild(marker);
  svg.appendChild(defs);

  orderedKinds.forEach((kind, index) => {
    const label = createSvg('text', {
      x: String(72 + index * 220),
      y: '44',
      fill: 'rgba(238, 244, 235, 0.78)',
      'font-size': '15',
      'font-family': 'Avenir Next Condensed, Franklin Gothic Medium, sans-serif',
      'letter-spacing': '0.08em',
    });
    label.textContent = kind;
    svg.appendChild(label);
  });

  const activePath = state.activePathIndex >= 0 ? state.paths[state.activePathIndex] : null;
  const activeNodeIds = new Set();
  const activeEdgeKeys = new Set();
  if (activePath) {
    activeNodeIds.add(activePath.start);
    activePath.steps.forEach((step) => {
      activeNodeIds.add(step.from);
      activeNodeIds.add(step.to);
      activeEdgeKeys.add(edgeKey(step));
    });
  }

  state.graph.edges.forEach((edge) => {
    const fromPos = positions.get(edge.From);
    const toPos = positions.get(edge.To);
    if (!fromPos || !toPos) {
      return;
    }

    const fromX = fromPos.x + fromPos.width;
    const fromY = fromPos.y + fromPos.height / 2;
    const toX = toPos.x;
    const toY = toPos.y + toPos.height / 2;
    const delta = Math.max(44, (toX - fromX) / 2);
    const pathData = `M ${fromX} ${fromY} C ${fromX + delta} ${fromY}, ${toX - delta} ${toY}, ${toX} ${toY}`;

    const path = createSvg('path', {
      d: pathData,
      class: `edge arrow${activePath && !activeEdgeKeys.has(graphEdgeKey(edge)) ? ' dim' : ''}${activeEdgeKeys.has(graphEdgeKey(edge)) ? ' active' : ''}`,
      'data-edge-key': graphEdgeKey(edge),
    });
    path.addEventListener('click', () => selectEdge(edge));
    svg.appendChild(path);

    const label = createSvg('text', {
      x: String((fromX + toX) / 2),
      y: String((fromY + toY) / 2 - 8),
      class: `edge-label${activePath && !activeEdgeKeys.has(graphEdgeKey(edge)) ? ' dim' : ''}`,
      'text-anchor': 'middle',
    });
    label.textContent = edge.Kind;
    svg.appendChild(label);
  });

  state.graph.nodes.forEach((node) => {
    const pos = positions.get(node.ID);
    if (!pos) {
      return;
    }

    const colors = nodeColor(node.Kind);
    const inPath = activeNodeIds.has(node.ID);
    const dim = activePath && !inPath;

    const group = createSvg('g', {
      class: `node${state.selectedNodeId === node.ID ? ' selected' : ''}${inPath ? ' in-path' : ''}${dim ? ' dim' : ''}`,
      transform: `translate(${pos.x}, ${pos.y})`,
    });
    group.addEventListener('click', () => selectNode(node.ID));

    group.appendChild(createSvg('rect', {
      width: String(pos.width),
      height: String(pos.height),
      fill: colors.fill,
      stroke: colors.stroke,
    }));

    const kindLabel = createSvg('text', { x: '12', y: '18', class: 'node-kind' });
    kindLabel.textContent = node.Kind;
    group.appendChild(kindLabel);

    nodeLabelLines(node).forEach((line, index) => {
      const text = createSvg('text', { x: '12', y: String(40 + index * 14) });
      text.textContent = line;
      group.appendChild(text);
    });

    svg.appendChild(group);
  });
}

function selectNode(nodeId) {
  state.selectedNodeId = nodeId;
  state.selectedEdgeKey = null;
  const node = getNode(nodeId);
  if (!node) {
    return;
  }
  els.selectedDetails.textContent = prettyJSON(node);
  renderGraph();
}

function selectEdge(edge) {
  state.selectedEdgeKey = graphEdgeKey(edge);
  state.selectedNodeId = null;
  els.selectedDetails.textContent = prettyJSON(edge);
  renderGraph();
}

function renderPaths() {
  if (!state.paths.length) {
    els.pathsList.innerHTML = '<div class="small-note">No attack paths loaded.</div>';
    updateStats();
    return;
  }

  els.pathsList.innerHTML = '';
  state.paths.forEach((path, index) => {
    const card = document.createElement('div');
    card.className = `path-card${index === state.activePathIndex ? ' active' : ''}`;
    const stepBadges = path.steps.slice(0, 4).map((step) => `<span class="badge">${escapeHTML(step.kind)}</span>`).join('');
    card.innerHTML = `
      <h3>${escapeHTML(path.goal_label)}</h3>
      <div class="path-meta">Start: ${escapeHTML(path.start_label)} | Score: ${path.score} | Steps: ${path.steps.length}</div>
      <div class="badge-row">${stepBadges}</div>
    `;
    card.addEventListener('click', () => {
      state.activePathIndex = index;
      const firstStep = path.steps[0];
      if (firstStep) {
        state.selectedNodeId = firstStep.from;
        const node = getNode(firstStep.from);
        if (node) {
          els.selectedDetails.textContent = prettyJSON(node);
        }
      }
      renderPaths();
      renderGraph();
      renderExplanationForPath(index);
    });
    els.pathsList.appendChild(card);
  });
  updateStats();
}

function renderScenarios(scenarios) {
  if (!Array.isArray(scenarios) || scenarios.length === 0) {
    els.scenarioList.innerHTML = '<div class="small-note">No scenario recommendations loaded.</div>';
    return;
  }

  els.scenarioList.innerHTML = scenarios.map((scenario) => `
    <div class="scenario-item">
      <strong>${escapeHTML(scenario.id)}</strong>
      <span class="scenario-command">${escapeHTML(scenario.command)}</span>
      <div class="small-note">${escapeHTML(scenario.reason)}</div>
    </div>
  `).join('');
}

function renderExplanation(explanations) {
  state.explanations = explanations || [];
  if (!state.explanations.length) {
    els.explainOutput.textContent = 'No explanation loaded.';
    renderScenarios([]);
    return;
  }

  const preferredIndex = state.activePathIndex >= 0 ? state.activePathIndex : 0;
  renderExplanationForPath(Math.min(preferredIndex, state.explanations.length - 1));
}

function renderExplanationForPath(index) {
  const explanation = state.explanations[index];
  if (!explanation) {
    els.explainOutput.textContent = 'No explanation loaded.';
    renderScenarios([]);
    return;
  }

  const lines = [];
  lines.push(`Start: ${explanation.start_label}`);
  lines.push(`Goal: ${explanation.goal_label}`);
  lines.push(`Score: ${explanation.score}`);
  lines.push('');

  explanation.steps.forEach((step, stepIndex) => {
    lines.push(`${stepIndex + 1}. ${step.from_label} -> ${step.to_label}`);
    lines.push(`   Edge: ${step.kind}`);
    lines.push(`   Why: ${step.why}`);
  });

  els.explainOutput.textContent = lines.join('\n');
  renderScenarios(explanation.scenarios || []);
}

function renderDiff(diff) {
  state.diff = diff;
  if (!diff) {
    els.diffOutput.textContent = 'No diff loaded.';
    return;
  }

  const lines = [];
  const sections = [
    ['Added nodes', diff.added_nodes || []],
    ['Removed nodes', diff.removed_nodes || []],
    ['Added edges', diff.added_edges || []],
    ['Removed edges', diff.removed_edges || []],
  ];

  sections.forEach(([title, items]) => {
    lines.push(`${title}: ${items.length}`);
    items.slice(0, 20).forEach((item) => {
      lines.push(`- ${JSON.stringify(item)}`);
    });
    lines.push('');
  });

  els.diffOutput.textContent = lines.join('\n').trim() || 'No diff loaded.';
}

function escapeHTML(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

async function loadGraph() {
  setStatus('Loading graph...');
  const graph = await fetchJSON(`/api/graph?${apiQuery()}`);
  state.graph = { nodes: graph.nodes || [], edges: graph.edges || [] };
  state.selectedNodeId = state.graph.nodes[0] ? state.graph.nodes[0].ID : null;
  if (state.selectedNodeId) {
    const node = getNode(state.selectedNodeId);
    if (node) {
      els.selectedDetails.textContent = prettyJSON(node);
    }
  } else {
    els.selectedDetails.textContent = 'Nothing selected.';
  }
  renderGraph();
  setStatus(`Loaded ${state.graph.nodes.length} nodes and ${state.graph.edges.length} edges.`);
}

async function loadPaths() {
  setStatus('Discovering paths...');
  const paths = await fetchJSON(`/api/paths?${apiQuery()}`);
  state.paths = Array.isArray(paths) ? paths : [];
  state.activePathIndex = state.paths.length ? 0 : -1;
  renderPaths();
  renderGraph();
  setStatus(`Loaded ${state.paths.length} attack path${state.paths.length === 1 ? '' : 's'}.`);
}

async function loadExplain() {
  setStatus('Explaining reachable paths...');
  const explanations = await fetchJSON(`/api/explain?${apiQuery({ top: els.top.value.trim() || '1' })}`);
  renderExplanation(Array.isArray(explanations) ? explanations : []);
  setStatus(`Loaded ${state.explanations.length} explanation${state.explanations.length === 1 ? '' : 's'}.`);
}

async function downloadSnapshot() {
  const graph = await fetchJSON(`/api/graph?${apiQuery()}`);
  const blob = new Blob([JSON.stringify(graph, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'attack-graph-snapshot.json';
  anchor.click();
  URL.revokeObjectURL(url);
  setStatus('Snapshot downloaded.');
}

async function runDiff() {
  const file = els.beforeFile.files[0];
  if (!file) {
    throw new Error('select a snapshot JSON file first');
  }
  setStatus('Comparing snapshot to live graph...');
  const before = JSON.parse(await file.text());
  const payload = {
    before,
    from: els.startRef.value.trim(),
    namespace: els.namespace.value.trim(),
  };
  const diff = await fetchJSON('/api/diff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  renderDiff(diff);
  setStatus('Diff loaded.');
}

async function runAction(action) {
  try {
    await action();
  } catch (error) {
    setStatus(error.message, true);
    console.error(error);
  }
}

function attachEvents() {
  els.loadGraphBtn.addEventListener('click', () => runAction(loadGraph));
  els.loadPathsBtn.addEventListener('click', () => runAction(loadPaths));
  els.explainBtn.addEventListener('click', () => runAction(loadExplain));
  els.downloadBtn.addEventListener('click', () => runAction(downloadSnapshot));
  els.diffBtn.addEventListener('click', () => runAction(runDiff));
  els.zoomOutBtn.addEventListener('click', () => setZoom(state.zoom - 0.2));
  els.zoomResetBtn.addEventListener('click', () => setZoom(1));
  els.zoomInBtn.addEventListener('click', () => setZoom(state.zoom + 0.2));

  els.graphSvg.parentElement.addEventListener('wheel', (event) => {
    if (!event.ctrlKey && !event.metaKey) {
      return;
    }
    event.preventDefault();
    const direction = event.deltaY > 0 ? -0.1 : 0.1;
    setZoom(state.zoom + direction);
  }, { passive: false });

  window.addEventListener('resize', () => {
    if (state.graph) {
      renderGraph();
    }
  });
}

async function bootstrap() {
  updateZoomLabel();
  attachEvents();
  await loadGraph();
  await loadPaths();
  await loadExplain();
}

runAction(bootstrap);
