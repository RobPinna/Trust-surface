/* Abuse path graph explorer for risk detail page. */
(function () {
  function normId(value) {
    return String(value || "").trim().toLowerCase();
  }

  function clean(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
  }

  function esc(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function maybeUrl(value) {
    var url = String(value || "").trim();
    if (!url) return "";
    if (url.indexOf("http://") === 0 || url.indexOf("https://") === 0) return url;
    return "";
  }

  function normalizeNumber(value, fallback) {
    var n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  }

  function classifyKind(text) {
    var t = String(text || "").toLowerCase();
    if (/(account|credential|password|login|mailbox|inbox|access)/.test(t)) return "Account";
    if (/(role|employee|staff|manager|finance|it |it-|privacy|person|team member)/.test(t)) return "Persona";
    if (/(email|linkedin|helpdesk|portal|channel|ticket|dm|message|chat|phone|whatsapp)/.test(t)) return "Channel";
    if (/(mfa|approval|policy|verify|verification|control|review|exception)/.test(t)) return "Control";
    if (/(asset|endpoint|server|workstation|device|domain|infrastructure)/.test(t)) return "Asset";
    return "Event";
  }

  function iconForKind(kind) {
    if (kind === "Asset") return "server";
    if (kind === "Account") return "user-cog";
    if (kind === "Persona") return "user-round";
    if (kind === "Channel") return "mail";
    if (kind === "Control") return "shield-check";
    return "activity";
  }

  function nodeTags(text) {
    var t = String(text || "").toLowerCase();
    var out = [];
    if (/(public|website|linkedin|press|news|jobs|contact page|published)/.test(t)) out.push("public");
    if (/(partner|vendor|supplier|outsource|external|third|3rd)/.test(t)) out.push("3rd party");
    if (/(email|call|chat|dm|message|persona|staff|team|social)/.test(t)) out.push("human");
    if (/(mfa|portal|login|token|vpn|endpoint|api|sso|admin|system)/.test(t)) out.push("technical");
    if (!out.length || !out.includes("public")) out.push("internal");
    if (out.length > 3) out = out.slice(0, 3);
    return out;
  }

  function relationForLink(link, source, target) {
    var label = clean((link && link.label) || "").toLowerCase();
    if (/(require|precondition|needs)/.test(label)) return "requires";
    if (/(trust|imperson|pretext|credib|social)/.test(label)) return "trust-lever";
    if (/(data|share|disclos|transfer|flow|handoff)/.test(label)) return "data-flow";
    if (/(enable|allow|pivot|advance|escalat|rejoin)/.test(label)) return "enables";
    if (source && source.kind === "Control") return "requires";
    if (source && source.kind === "Channel") return "trust-lever";
    if (target && target.kind === "Account") return "trust-lever";
    return "enables";
  }

  function relationClass(rel) {
    if (rel === "requires") return "is-requires";
    if (rel === "trust-lever") return "is-trust-lever";
    if (rel === "data-flow") return "is-data-flow";
    return "is-enables";
  }

  function relationBoost(rel) {
    if (rel === "trust-lever") return 1.2;
    if (rel === "data-flow") return 0.9;
    if (rel === "requires") return 0.45;
    return 0.7;
  }

  function buildStageMap(graph) {
    var stageByNode = {};
    var cols = Array.isArray(graph.columns) ? graph.columns : [];
    for (var c = 0; c < cols.length; c += 1) {
      var col = cols[c];
      var colStage = normalizeNumber(col && col.stage, c);
      var colNodes = Array.isArray(col && col.nodes) ? col.nodes : [];
      for (var j = 0; j < colNodes.length; j += 1) {
        var colNodeId = normId(colNodes[j] && colNodes[j].id);
        if (colNodeId) stageByNode[colNodeId] = colStage;
      }
    }
    return stageByNode;
  }

  function buildBaseEvidenceMap(vm) {
    var out = {};
    var storyNodes = (((vm || {}).story_map || {}).abuse_path_graph || {}).nodes || [];
    for (var i = 0; i < storyNodes.length; i += 1) {
      var sn = storyNodes[i] || {};
      var sid = normId(sn.id);
      if (sid && sn.evidence_set_id) out[sid] = sn.evidence_set_id;
    }
    return out;
  }

  window.__abuseExplorerUtils = {
    normId: normId,
    clean: clean,
    esc: esc,
    maybeUrl: maybeUrl,
    normalizeNumber: normalizeNumber,
    classifyKind: classifyKind,
    iconForKind: iconForKind,
    nodeTags: nodeTags,
    relationForLink: relationForLink,
    relationClass: relationClass,
    relationBoost: relationBoost,
    buildStageMap: buildStageMap,
    buildBaseEvidenceMap: buildBaseEvidenceMap,
  };
})();

(function () {
  function stageGroups(nodes) {
    var groups = {};
    for (var i = 0; i < nodes.length; i += 1) {
      var st = nodes[i].stage;
      if (!groups[st]) groups[st] = [];
      groups[st].push(nodes[i]);
    }
    var stages = Object.keys(groups).map(function (x) { return Number(x); }).sort(function (a, b) { return a - b; });
    return { groups: groups, stages: stages };
  }

  function centeredOffset(index, count, spacing, maxAbs) {
    if (!count || count <= 1) return 0;
    var raw = (index - ((count - 1) / 2)) * spacing;
    if (raw > maxAbs) return maxAbs;
    if (raw < -maxAbs) return -maxAbs;
    return raw;
  }

  function overlap(a1, a2, b1, b2) {
    return Math.max(a1, b1) <= Math.min(a2, b2);
  }

  function computeCriticalPath(nodes, links, nodeById, adj, relationBoost) {
    var minStage = Infinity;
    for (var i = 0; i < nodes.length; i += 1) minStage = Math.min(minStage, nodes[i].stage);
    var roots = nodes.filter(function (n) { return n.stage === minStage; });
    var ordered = nodes.slice().sort(function (a, b) {
      if (a.stage !== b.stage) return a.stage - b.stage;
      return a.id.localeCompare(b.id);
    });
    var score = {};
    var prev = {};
    for (var j = 0; j < ordered.length; j += 1) score[ordered[j].id] = -999999;
    for (var x = 0; x < roots.length; x += 1) score[roots[x].id] = 0;

    for (var m = 0; m < ordered.length; m += 1) {
      var node = ordered[m];
      var out = adj[node.id] || [];
      for (var n = 0; n < out.length; n += 1) {
        var edge = out[n];
        var sourceNode = nodeById[edge.source];
        var targetNode = nodeById[edge.target];
        if (!sourceNode || !targetNode || targetNode.stage < sourceNode.stage) continue;
        var candidate = score[sourceNode.id] + edge.weight + relationBoost(edge.relation);
        if (candidate > (score[targetNode.id] || -999999)) {
          score[targetNode.id] = candidate;
          prev[targetNode.id] = edge.id;
        }
      }
    }

    var bestNode = ordered[0] || null;
    var bestScore = -999999;
    for (var q = 0; q < ordered.length; q += 1) {
      if ((score[ordered[q].id] || -999999) > bestScore) {
        bestScore = score[ordered[q].id];
        bestNode = ordered[q];
      }
    }
    var edgeSet = {};
    var nodeSet = {};
    if (bestNode) nodeSet[bestNode.id] = true;
    var guard = 0;
    while (bestNode && prev[bestNode.id] && guard < 200) {
      guard += 1;
      var peid = prev[bestNode.id];
      var pedge = null;
      for (var z = 0; z < links.length; z += 1) {
        if (links[z].id === peid) {
          pedge = links[z];
          break;
        }
      }
      if (!pedge) break;
      edgeSet[pedge.id] = true;
      nodeSet[pedge.source] = true;
      nodeSet[pedge.target] = true;
      bestNode = nodeById[pedge.source] || null;
    }
    if (!Object.keys(nodeSet).length && nodes.length) nodeSet[nodes[0].id] = true;
    return { nodes: nodeSet, edges: edgeSet };
  }

  function walk(nodeId, map, reverse) {
    var visitedNodes = {};
    var visitedEdges = {};
    var stack = [nodeId];
    while (stack.length) {
      var cur = stack.pop();
      if (!cur || visitedNodes[cur]) continue;
      visitedNodes[cur] = true;
      var rows = map[cur] || [];
      for (var i = 0; i < rows.length; i += 1) {
        var edge = rows[i];
        visitedEdges[edge.id] = true;
        var nxt = reverse ? edge.source : edge.target;
        if (!visitedNodes[nxt]) stack.push(nxt);
      }
    }
    return { nodes: visitedNodes, edges: visitedEdges };
  }

  window.initAbuseExplorer = function initAbuseExplorer(vm) {
    var utils = window.__abuseExplorerUtils || {};
    var normId = utils.normId;
    var clean = utils.clean;
    var esc = utils.esc;
    var maybeUrl = utils.maybeUrl;
    var normalizeNumber = utils.normalizeNumber;
    var classifyKind = utils.classifyKind;
    var iconForKind = utils.iconForKind;
    var nodeTags = utils.nodeTags;
    var relationForLink = utils.relationForLink;
    var relationClass = utils.relationClass;
    var relationBoost = utils.relationBoost;
    var buildStageMap = utils.buildStageMap;
    var buildBaseEvidenceMap = utils.buildBaseEvidenceMap;

    var explorer = document.getElementById("abuseExplorer");
    if (!explorer || !normId) return;

    var graph = (((vm || {}).story_map || {}).abuse_path_graph) || {};
    var rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    var rawLinks = Array.isArray(graph.links) ? graph.links : [];
    if (!rawNodes.length) return;

    var canvas = document.getElementById("abuseGraphCanvas");
    var svg = document.getElementById("abuseGraphSvg");
    var nodeLayer = document.getElementById("abuseGraphNodes");
    var detailPanel = document.getElementById("abuseStepDetails");
    var criticalToggle = document.getElementById("abuseCriticalToggle");
    if (!canvas || !svg || !nodeLayer || !detailPanel) return;

    var evidenceSets = (vm && vm.evidenceSets) ? vm.evidenceSets : {};
    var stageByNode = buildStageMap(graph);
    var baseEvidenceByNode = buildBaseEvidenceMap(vm);

    var nodes = [];
    var nodeById = {};
    for (var i = 0; i < rawNodes.length; i += 1) {
      var row = rawNodes[i] || {};
      var id = normId(row.id || ("n" + (i + 1)));
      if (!id || nodeById[id]) continue;
      var title = clean(row.title || ("Step " + (nodes.length + 1)));
      var detail = clean(row.detail || "");
      var stage = normalizeNumber(row.stage, stageByNode[id]);
      if (!Number.isFinite(stage)) stage = nodes.length;
      var kind = classifyKind(title + " " + detail);
      var tags = nodeTags(title + " " + detail);
      var evidenceSetId = clean(row.evidence_set_id || baseEvidenceByNode[id] || "");
      var node = {
        id: id,
        title: title,
        detail: detail,
        stage: stage,
        kind: kind,
        icon: iconForKind(kind),
        tags: tags,
        evidence_set_id: evidenceSetId,
      };
      nodes.push(node);
      nodeById[id] = node;
    }
    nodes.sort(function (a, b) {
      if (a.stage !== b.stage) return a.stage - b.stage;
      return a.title.localeCompare(b.title);
    });

    var links = [];
    var linkSeen = {};
    for (var l = 0; l < rawLinks.length; l += 1) {
      var edge = rawLinks[l] || {};
      var sourceId = normId(edge.source);
      var targetId = normId(edge.target);
      if (!sourceId || !targetId || sourceId === targetId || !nodeById[sourceId] || !nodeById[targetId]) continue;
      var key = sourceId + "|" + targetId;
      if (linkSeen[key]) continue;
      linkSeen[key] = true;
      links.push({
        id: "e" + (links.length + 1),
        source: sourceId,
        target: targetId,
        label: clean(edge.label || ""),
        weight: Math.max(1, Math.min(5, normalizeNumber(edge.weight, 2))),
        synthetic: false,
      });
    }

    var sg = stageGroups(nodes);
    var groups = sg.groups;
    var stages = sg.stages;
    var inCount = {};
    var outCount = {};
    for (var ii = 0; ii < links.length; ii += 1) {
      outCount[links[ii].source] = (outCount[links[ii].source] || 0) + 1;
      inCount[links[ii].target] = (inCount[links[ii].target] || 0) + 1;
    }
    for (var s = 0; s < stages.length - 1; s += 1) {
      var current = groups[stages[s]] || [];
      var next = groups[stages[s + 1]] || [];
      if (!current.length || !next.length) continue;
      for (var a = 0; a < current.length; a += 1) {
        var src = current[a];
        if (outCount[src.id]) continue;
        var dst = next[Math.min(a, next.length - 1)];
        links.push({ id: "e" + (links.length + 1), source: src.id, target: dst.id, label: "stitch path", weight: 1, synthetic: true });
        outCount[src.id] = 1;
        inCount[dst.id] = (inCount[dst.id] || 0) + 1;
      }
      for (var b = 0; b < next.length; b += 1) {
        var targetNode = next[b];
        if (inCount[targetNode.id]) continue;
        var sourceNode = current[Math.min(b, current.length - 1)];
        links.push({ id: "e" + (links.length + 1), source: sourceNode.id, target: targetNode.id, label: "stitch path", weight: 1, synthetic: true });
        outCount[sourceNode.id] = (outCount[sourceNode.id] || 0) + 1;
        inCount[targetNode.id] = 1;
      }
    }

    for (var r = 0; r < links.length; r += 1) {
      var srcNode = nodeById[links[r].source];
      var dstNode = nodeById[links[r].target];
      links[r].relation = relationForLink(links[r], srcNode, dstNode);
    }

    var adj = {};
    var rev = {};
    for (var k = 0; k < links.length; k += 1) {
      var e = links[k];
      if (!adj[e.source]) adj[e.source] = [];
      if (!rev[e.target]) rev[e.target] = [];
      adj[e.source].push(e);
      rev[e.target].push(e);
    }

    var critical = computeCriticalPath(nodes, links, nodeById, adj, relationBoost);
    var state = {
      selectedNodeId: nodes.length ? nodes[0].id : "",
      criticalOnly: false,
      activeNodeSet: {},
      activeEdgeSet: {},
      panX: 0,
      panY: 0,
      isPanning: false,
      panStartX: 0,
      panStartY: 0,
      panOriginX: 0,
      panOriginY: 0,
      panInitialized: false,
      suppressNextClick: false,
    };
    var lastLayout = null;

    var WORLD_PAD_X = 44;
    var WORLD_PAD_Y = 26;

    function clampPan(nx, ny) {
      if (!lastLayout || !canvas) return { x: nx, y: ny };
      var vw = Math.max(1, canvas.clientWidth || 1);
      var vh = Math.max(1, canvas.clientHeight || 1);
      var worldW = Math.max(1, Number(lastLayout.width || vw));
      var worldH = Math.max(1, Number(lastLayout.height || vh));
      var minX;
      var maxX;
      var minY;
      var maxY;
      if (worldW <= vw) {
        minX = maxX = Math.round((vw - worldW) / 2);
      } else {
        minX = Math.round(vw - worldW - WORLD_PAD_X);
        maxX = WORLD_PAD_X;
      }
      if (worldH <= vh) {
        minY = maxY = Math.round((vh - worldH) / 2);
      } else {
        minY = Math.round(vh - worldH - WORLD_PAD_Y);
        maxY = WORLD_PAD_Y;
      }
      var x = Math.max(minX, Math.min(maxX, nx));
      var y = Math.max(minY, Math.min(maxY, ny));
      return { x: x, y: y };
    }

    function applyPanTransform() {
      if (!svg || !nodeLayer) return;
      var t = "translate(" + state.panX + "px, " + state.panY + "px)";
      svg.style.transform = t;
      svg.style.transformOrigin = "top left";
      nodeLayer.style.transform = t;
      nodeLayer.style.transformOrigin = "top left";
    }

    function computeActiveSets() {
      var allNodes = {};
      var allEdges = {};
      for (var i = 0; i < nodes.length; i += 1) allNodes[nodes[i].id] = true;
      for (var j = 0; j < links.length; j += 1) allEdges[links[j].id] = true;

      var activeNodes = {};
      var activeEdges = {};
      if (state.selectedNodeId && nodeById[state.selectedNodeId]) {
        var fw = walk(state.selectedNodeId, adj, false);
        var bw = walk(state.selectedNodeId, rev, true);
        Object.keys(fw.nodes).forEach(function (id) { activeNodes[id] = true; });
        Object.keys(bw.nodes).forEach(function (id) { activeNodes[id] = true; });
        Object.keys(fw.edges).forEach(function (id) { activeEdges[id] = true; });
        Object.keys(bw.edges).forEach(function (id) { activeEdges[id] = true; });
      } else {
        activeNodes = allNodes;
        activeEdges = allEdges;
      }

      if (state.criticalOnly) {
        var critNodes = critical.nodes || {};
        var critEdges = critical.edges || {};
        var filteredNodes = {};
        var filteredEdges = {};
        Object.keys(activeNodes).forEach(function (id) {
          if (critNodes[id]) filteredNodes[id] = true;
        });
        Object.keys(activeEdges).forEach(function (id) {
          if (critEdges[id]) filteredEdges[id] = true;
        });
        if (!Object.keys(filteredNodes).length) filteredNodes = critNodes;
        if (!Object.keys(filteredEdges).length) filteredEdges = critEdges;
        activeNodes = filteredNodes;
        activeEdges = filteredEdges;
      }

      state.activeNodeSet = activeNodes;
      state.activeEdgeSet = activeEdges;
    }

    function buildOrderedStages(stageList, groupsByStage) {
      var ordered = {};
      for (var i = 0; i < stageList.length; i += 1) {
        var st = stageList[i];
        var base = (groupsByStage[st] || []).slice();
        base.sort(function (a, b) { return a.title.localeCompare(b.title); });
        ordered[st] = base;
      }

      function rebuildIndexMap() {
        var map = {};
        for (var si = 0; si < stageList.length; si += 1) {
          var stage = stageList[si];
          var arr = ordered[stage] || [];
          for (var ai = 0; ai < arr.length; ai += 1) map[arr[ai].id] = ai;
        }
        return map;
      }

      function barycenter(node, edgeMap, useSource, indexMap) {
        var rows = edgeMap[node.id] || [];
        if (!rows.length) return Number.POSITIVE_INFINITY;
        var sum = 0;
        var cnt = 0;
        for (var ri = 0; ri < rows.length; ri += 1) {
          var eid = useSource ? rows[ri].source : rows[ri].target;
          if (indexMap[eid] === undefined) continue;
          sum += indexMap[eid];
          cnt += 1;
        }
        if (!cnt) return Number.POSITIVE_INFINITY;
        return sum / cnt;
      }

      function totalDegree(node) {
        return ((adj[node.id] || []).length || 0) + ((rev[node.id] || []).length || 0);
      }

      var indexMap = rebuildIndexMap();
      for (var iter = 0; iter < 3; iter += 1) {
        for (var f = 1; f < stageList.length; f += 1) {
          var fStage = stageList[f];
          var fRows = (ordered[fStage] || []).slice();
          fRows.sort(function (a, b) {
            var ba = barycenter(a, rev, true, indexMap);
            var bb = barycenter(b, rev, true, indexMap);
            if (Number.isFinite(ba) && Number.isFinite(bb) && Math.abs(ba - bb) > 0.001) return ba - bb;
            if (Number.isFinite(ba) && !Number.isFinite(bb)) return -1;
            if (!Number.isFinite(ba) && Number.isFinite(bb)) return 1;
            var da = totalDegree(a);
            var db = totalDegree(b);
            if (da !== db) return db - da;
            return a.title.localeCompare(b.title);
          });
          ordered[fStage] = fRows;
          indexMap = rebuildIndexMap();
        }

        for (var b = stageList.length - 2; b >= 0; b -= 1) {
          var bStage = stageList[b];
          var bRows = (ordered[bStage] || []).slice();
          bRows.sort(function (a, c) {
            var ba = barycenter(a, adj, false, indexMap);
            var bb = barycenter(c, adj, false, indexMap);
            if (Number.isFinite(ba) && Number.isFinite(bb) && Math.abs(ba - bb) > 0.001) return ba - bb;
            if (Number.isFinite(ba) && !Number.isFinite(bb)) return -1;
            if (!Number.isFinite(ba) && Number.isFinite(bb)) return 1;
            var da = totalDegree(a);
            var db = totalDegree(c);
            if (da !== db) return db - da;
            return a.title.localeCompare(c.title);
          });
          ordered[bStage] = bRows;
          indexMap = rebuildIndexMap();
        }
      }
      return ordered;
    }

    function stageBranchMetrics(stageNodes) {
      var maxBranch = 0;
      var branchNodes = 0;
      for (var i = 0; i < stageNodes.length; i += 1) {
        var node = stageNodes[i];
        var outDeg = ((adj[node.id] || []).length || 0);
        var inDeg = ((rev[node.id] || []).length || 0);
        var branchScore = Math.max(0, Math.max(outDeg, inDeg) - 1);
        if (branchScore > 0) branchNodes += 1;
        if (branchScore > maxBranch) maxBranch = branchScore;
      }
      return {
        maxBranch: maxBranch,
        branchNodes: branchNodes,
        branchRatio: stageNodes.length ? (branchNodes / stageNodes.length) : 0,
      };
    }

    function computeLayout() {
      var viewportWidth = Math.max(360, canvas ? canvas.clientWidth : 720);
      var sgRows = stageGroups(nodes);
      var stageList = sgRows.stages;
      var groupsByStage = sgRows.groups;
      var orderedByStage = buildOrderedStages(stageList, groupsByStage);
      var stageCount = Math.max(1, stageList.length || 1);
      // Linear spacing (no edge compression) + adaptive node width to prevent overlaps.
      var targetNodeW = viewportWidth < 760 ? 96 : (viewportWidth < 1020 ? 104 : 112);
      var outerPad = viewportWidth < 760 ? 18 : 26;
      var minColGap = viewportWidth < 760 ? 18 : 26;
      var desiredStep = viewportWidth < 760 ? 170 : 190;
      var width = viewportWidth;
      if (stageCount > 1) {
        var neededWidth = Math.round((2 * outerPad) + (desiredStep * (stageCount - 1)));
        if (neededWidth > width) width = neededWidth;
      }
      targetNodeW = width < 760 ? 96 : (width < 1020 ? 104 : 112);
      outerPad = width < 760 ? 18 : 26;
      minColGap = width < 760 ? 18 : 26;
      var nodeW = targetNodeW;
      var stageStep = 0;
      var xPad = outerPad;
      var nodeHalfPad = Math.ceil(nodeW / 2);
      var lanePad = 26;
      var innerPadX = Math.max(WORLD_PAD_X, outerPad + nodeHalfPad + lanePad);
      if (stageCount > 1) {
        var rawStep = (width - (2 * innerPadX)) / (stageCount - 1);
        var maxNodeWByStep = Math.floor(rawStep - minColGap);
        nodeW = Math.max(72, Math.min(targetNodeW, maxNodeWByStep));
        nodeHalfPad = Math.ceil(nodeW / 2);
        innerPadX = Math.max(WORLD_PAD_X, outerPad + nodeHalfPad + lanePad);
        var minWidthForColumns = Math.round((2 * innerPadX) + ((nodeW + minColGap) * (stageCount - 1)));
        if (minWidthForColumns > width) width = minWidthForColumns;
        stageStep = Math.max(1, ((width - (2 * innerPadX)) / (stageCount - 1)));
        if (stageStep < (nodeW + minColGap)) {
          nodeW = Math.max(68, Math.floor(stageStep - minColGap));
          nodeHalfPad = Math.ceil(nodeW / 2);
          innerPadX = Math.max(WORLD_PAD_X, outerPad + nodeHalfPad + lanePad);
          minWidthForColumns = Math.round((2 * innerPadX) + ((nodeW + minColGap) * (stageCount - 1)));
          if (minWidthForColumns > width) width = minWidthForColumns;
          stageStep = Math.max(1, ((width - (2 * innerPadX)) / (stageCount - 1)));
        }
        var usedWidth = stageStep * (stageCount - 1);
        xPad = Math.max(innerPadX, Math.floor((width - usedWidth) / 2));
      } else {
        nodeW = Math.min(targetNodeW, Math.max(82, Math.floor((width - (2 * WORLD_PAD_X)) * 0.56)));
        xPad = Math.floor(width / 2);
      }
      var nodeH = 102;
      var yPad = Math.max(28, WORLD_PAD_Y);
      var maxCols = stageCount; // always horizontal across full graph width
      var rowCount = 1;
      var positions = {};
      var yCursor = yPad;
      var baseVGap = 30;
      var branchVGap = 52;
      var extraBranchBand = 60;

      for (var row = 0; row < rowCount; row += 1) {
        var rowStages = stageList.slice(row * maxCols, (row + 1) * maxCols);
        var bandMaxNodes = 1;
        var rowHasBranching = false;
        var stageGapMap = {};
        var stageMetricMap = {};
        for (var x = 0; x < rowStages.length; x += 1) {
          var stageNodes = (orderedByStage[rowStages[x]] || []);
          var metrics = stageBranchMetrics(stageNodes);
          stageMetricMap[rowStages[x]] = metrics;
          var stageHasBranch = metrics.maxBranch > 0 || stageNodes.length > 1;
          if (stageHasBranch) rowHasBranching = true;
          var dynamicGap = baseVGap
            + (stageHasBranch ? 12 : 0)
            + Math.min(20, metrics.maxBranch * 8)
            + Math.round(metrics.branchRatio * 10);
          stageGapMap[rowStages[x]] = Math.max(baseVGap, Math.min(branchVGap + 24, dynamicGap));
          bandMaxNodes = Math.max(bandMaxNodes, stageNodes.length || 1);
        }
        var bandStep = rowHasBranching ? Math.max(branchVGap, baseVGap + 16) : baseVGap;
        var bandHeight = Math.max(
          rowHasBranching ? 320 : 232,
          56 + (bandMaxNodes * (nodeH + bandStep)) + (rowHasBranching ? extraBranchBand : 0)
        );
        var rowCols = rowStages.length || 1;

        for (var c = 0; c < rowStages.length; c += 1) {
          var stage = rowStages[c];
          var colNodes = (orderedByStage[stage] || []).slice();
          var t = rowCols <= 1 ? 0.5 : (c / (rowCols - 1));
          var xPos = rowCols === 1 ? Math.floor(width / 2) : Math.round(xPad + (c * stageStep));
          var nodeGap = stageGapMap[stage] || baseVGap;
          var stageBranch = nodeGap > baseVGap;
          var stageMetrics = stageMetricMap[stage] || { maxBranch: 0, branchRatio: 0 };
          var stageWave = Math.round(Math.sin(Math.PI * t) * (rowHasBranching ? 12 : 6));
          var colHeight = (colNodes.length * nodeH) + (Math.max(0, colNodes.length - 1) * nodeGap);
          // For branch-heavy stages, place nodes a bit lower to separate branch curves.
          var startY = stageBranch
            ? (yCursor + Math.max(28, Math.floor(bandHeight * (0.18 + (0.05 * Math.min(2, stageMetrics.maxBranch))))) + stageWave)
            : (yCursor + Math.max(16, Math.floor((bandHeight - colHeight) / 2)) + stageWave);
          var maxStart = yCursor + bandHeight - 20 - colHeight;
          if (startY > maxStart) startY = maxStart;
          if (startY < (yCursor + 12)) startY = yCursor + 12;
          for (var n = 0; n < colNodes.length; n += 1) {
            var centerY = startY + (n * (nodeH + nodeGap)) + Math.floor(nodeH / 2);
            positions[colNodes[n].id] = {
              cx: xPos,
              cy: centerY,
              w: nodeW,
              h: nodeH,
              left: xPos - Math.floor(nodeW / 2),
              right: xPos + Math.floor(nodeW / 2),
              top: centerY - Math.floor(nodeH / 2),
              bottom: centerY + Math.floor(nodeH / 2),
            };
          }
        }
        yCursor += bandHeight + (rowHasBranching ? 32 : 22);
      }
      return { width: width, height: Math.max(420, yCursor + WORLD_PAD_Y), positions: positions };
    }

    function edgePath(src, dst, opts, maxY) {
      if (!src || !dst) return "";
      opts = opts || {};
      var syOffset = normalizeNumber(opts.syOffset, 0);
      var tyOffset = normalizeNumber(opts.tyOffset, 0);
      var laneIndex = Math.max(0, Math.floor(normalizeNumber(opts.laneIndex, 0)));
      var safeLaneY = normalizeNumber(opts.safeLaneY, NaN);
      var safeSideX = normalizeNumber(opts.safeSideX, NaN);
      var forward = dst.cx > src.cx + 16;
      var backward = dst.cx < src.cx - 16;

      function smoothPolyline(points, radius) {
        if (!Array.isArray(points) || points.length < 2) return "";
        var r = Math.max(0, Number(radius || 0));
        var out = "";
        function p(i) { return points[i] || [0, 0]; }
        function dist(a, b) {
          var dx = b[0] - a[0];
          var dy = b[1] - a[1];
          return Math.sqrt((dx * dx) + (dy * dy));
        }
        function unit(a, b) {
          var d = dist(a, b) || 1;
          return [(b[0] - a[0]) / d, (b[1] - a[1]) / d];
        }
        out += "M " + p(0)[0] + " " + p(0)[1];
        if (points.length === 2 || r <= 0) {
          for (var li = 1; li < points.length; li += 1) out += " L " + p(li)[0] + " " + p(li)[1];
          return out;
        }

        for (var i = 1; i < points.length - 1; i += 1) {
          var prev = p(i - 1);
          var curr = p(i);
          var next = p(i + 1);
          var inLen = dist(prev, curr);
          var outLen = dist(curr, next);
          if (inLen < 0.001 || outLen < 0.001) {
            out += " L " + curr[0] + " " + curr[1];
            continue;
          }
          var rr = Math.min(r, (inLen * 0.45), (outLen * 0.45));
          var uIn = unit(curr, prev);
          var uOut = unit(curr, next);
          var inPt = [curr[0] + (uIn[0] * rr), curr[1] + (uIn[1] * rr)];
          var outPt = [curr[0] + (uOut[0] * rr), curr[1] + (uOut[1] * rr)];
          out += " L " + inPt[0] + " " + inPt[1];
          out += " Q " + curr[0] + " " + curr[1] + ", " + outPt[0] + " " + outPt[1];
        }
        var last = p(points.length - 1);
        out += " L " + last[0] + " " + last[1];
        return out;
      }

      function horizontalDetourPath(isForward, laneY) {
        var elbowOut = 18 + (laneIndex * 6);
        if (isForward) {
          var sx = src.right;
          var sy = src.cy + syOffset;
          var tx = dst.left;
          var ty = dst.cy + tyOffset;
          var x1 = sx + elbowOut;
          var x2 = tx - elbowOut;
          if (x2 < x1 + 8) {
            var mid = Math.round((sx + tx) / 2);
            x1 = mid - 4;
            x2 = mid + 4;
          }
          return smoothPolyline(
            [[sx, sy], [x1, sy], [x1, laneY], [x2, laneY], [x2, ty], [tx, ty]],
            9
          );
        }
        var bsx = src.left;
        var bsy = src.cy + syOffset;
        var btx = dst.right;
        var bty = dst.cy + tyOffset;
        var bx1 = bsx - elbowOut;
        var bx2 = btx + elbowOut;
        if (bx1 < bx2 + 8) {
          var bmid = Math.round((bsx + btx) / 2);
          bx1 = bmid + 4;
          bx2 = bmid - 4;
        }
        return smoothPolyline(
          [[bsx, bsy], [bx1, bsy], [bx1, laneY], [bx2, laneY], [bx2, bty], [btx, bty]],
          9
        );
      }

      if (forward) {
        var fsx = src.right;
        var fsy = src.cy + syOffset;
        var ftx = dst.left;
        var fty = dst.cy + tyOffset;
        if (Number.isFinite(safeLaneY)) {
          return horizontalDetourPath(true, Math.max(WORLD_PAD_Y, Math.min(maxY - WORLD_PAD_Y, safeLaneY)));
        }
        var dx = Math.max(22, Math.min(90, (ftx - fsx) * 0.42));
        return "M " + fsx + " " + fsy + " C " + (fsx + dx) + " " + fsy + ", " + (ftx - dx) + " " + fty + ", " + ftx + " " + fty;
      }

      if (backward) {
        if (Number.isFinite(safeLaneY)) {
          return horizontalDetourPath(false, Math.max(WORLD_PAD_Y, Math.min(maxY - WORLD_PAD_Y, safeLaneY)));
        }
        var laneGap = 16;
        var tier = Math.floor(laneIndex / 2);
        var below = (laneIndex % 2) === 0;
        var lane = Number.isFinite(safeLaneY) ? safeLaneY : (
          below
          ? (Math.max(src.bottom, dst.bottom) + 22 + (tier * laneGap))
          : (Math.min(src.top, dst.top) - 22 - (tier * laneGap))
        );
        lane = Math.max(WORLD_PAD_Y, Math.min(maxY - WORLD_PAD_Y, lane));
        var bsx = src.cx;
        var bsy = lane > src.cy ? (src.bottom + syOffset) : (src.top + syOffset);
        var btx = dst.cx;
        var bty = lane > dst.cy ? (dst.bottom + tyOffset) : (dst.top + tyOffset);
        var midX = Math.round((bsx + btx) / 2);
        return "M " + bsx + " " + bsy + " C " + bsx + " " + lane + ", " + midX + " " + lane + ", " + midX + " " + lane
          + " C " + midX + " " + lane + ", " + btx + " " + lane + ", " + btx + " " + bty;
      }

      var sideGap = 18 + (laneIndex * 10);
      var rightSideX = Number.isFinite(safeSideX) ? safeSideX : (Math.max(src.right, dst.right) + sideGap);
      var leftSideX = Number.isFinite(safeSideX) ? safeSideX : (Math.min(src.left, dst.left) - sideGap);
      var routeRight = Number.isFinite(safeSideX) ? (safeSideX >= Math.max(src.cx, dst.cx)) : (rightSideX <= (src.left + (dst.left - src.left) + 120));
      var sideX = routeRight ? rightSideX : leftSideX;
      var vsx = routeRight ? src.right : src.left;
      var vsy = src.cy + syOffset;
      var vtx = routeRight ? dst.right : dst.left;
      var vty = dst.cy + tyOffset;
      return "M " + vsx + " " + vsy + " C " + sideX + " " + vsy + ", " + sideX + " " + vty + ", " + vtx + " " + vty;
    }

    function renderDetails() {
      var node = nodeById[state.selectedNodeId] || null;
      if (!node) {
        detailPanel.innerHTML = '<p class="kpi-label">Step details</p><p class="item-meta mt-2">Select a node to inspect role, tags, and graph connections.</p>';
        return;
      }

      var relatedIn = (rev[node.id] || []).slice(0, 4);
      var relatedOut = (adj[node.id] || []).slice(0, 4);
      var incoming = relatedIn.map(function (e) {
        var src = nodeById[e.source];
        return "<li>" + esc(src ? src.title : e.source) + ' <span class="abuse-mini-rel">' + esc(e.relation) + "</span></li>";
      }).join("");
      var outgoing = relatedOut.map(function (e) {
        var dst = nodeById[e.target];
        return '<li><span class="abuse-mini-rel">' + esc(e.relation) + "</span> " + esc(dst ? dst.title : e.target) + "</li>";
      }).join("");
      var tags = (node.tags || []).map(function (t) { return '<span class="abuse-node-tag">' + esc(t) + "</span>"; }).join("");
      var evidenceCount = (node.evidence_set_id && evidenceSets[node.evidence_set_id]) ? evidenceSets[node.evidence_set_id].length : 0;

      detailPanel.innerHTML =
        '<div class="abuse-step-head">' +
        '<span class="abuse-step-kind"><i data-lucide="' + esc(node.icon) + '"></i>' + esc(node.kind) + "</span>" +
        "</div>" +
        '<h4 class="abuse-step-title">' + esc(node.title) + "</h4>" +
        '<p class="abuse-step-desc">' + esc(node.detail || "No detail available.") + "</p>" +
        '<div class="abuse-node-tags">' + tags + "</div>" +
        '<p class="abuse-step-evidence-count">Evidence linked: ' + String(evidenceCount) + "</p>" +
        '<div class="abuse-step-io">' +
        "<div><p class=\"kpi-label\">Incoming</p><ul>" + (incoming || '<li class="item-meta">No incoming links.</li>') + "</ul></div>" +
        "<div><p class=\"kpi-label\">Outgoing</p><ul>" + (outgoing || '<li class="item-meta">No outgoing links.</li>') + "</ul></div>" +
        "</div>";

      if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
    }

    function renderGraph() {
      var layout = computeLayout();
      var viewportHeight = Math.min(layout.height, 520);
      canvas.style.height = String(viewportHeight) + "px";
      lastLayout = { width: layout.width, height: layout.height };
      if (!state.panInitialized) {
        var first = clampPan(Math.round((canvas.clientWidth - layout.width) / 2), Math.round((viewportHeight - layout.height) / 2));
        state.panX = first.x;
        state.panY = first.y;
        state.panInitialized = true;
      } else {
        var clamped = clampPan(state.panX, state.panY);
        state.panX = clamped.x;
        state.panY = clamped.y;
      }
      svg.setAttribute("viewBox", "0 0 " + layout.width + " " + layout.height);
      svg.setAttribute("width", String(layout.width));
      svg.setAttribute("height", String(layout.height));
      nodeLayer.style.width = String(layout.width) + "px";
      nodeLayer.style.height = String(layout.height) + "px";
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      while (nodeLayer.firstChild) nodeLayer.removeChild(nodeLayer.firstChild);

      var outPortOffsetByEdge = {};
      var inPortOffsetByEdge = {};

      Object.keys(adj).forEach(function (nodeId) {
        var outEdges = (adj[nodeId] || []).slice();
        outEdges.sort(function (a, b) {
          var ay = ((layout.positions[a.target] || {}).cy || 0);
          var by = ((layout.positions[b.target] || {}).cy || 0);
          if (ay !== by) return ay - by;
          return a.id.localeCompare(b.id);
        });
        for (var oi = 0; oi < outEdges.length; oi += 1) {
          outPortOffsetByEdge[outEdges[oi].id] = centeredOffset(oi, outEdges.length, 7, 18);
        }
      });

      Object.keys(rev).forEach(function (nodeId) {
        var inEdges = (rev[nodeId] || []).slice();
        inEdges.sort(function (a, b) {
          var ay = ((layout.positions[a.source] || {}).cy || 0);
          var by = ((layout.positions[b.source] || {}).cy || 0);
          if (ay !== by) return ay - by;
          return a.id.localeCompare(b.id);
        });
        for (var ii = 0; ii < inEdges.length; ii += 1) {
          inPortOffsetByEdge[inEdges[ii].id] = centeredOffset(ii, inEdges.length, 7, 18);
        }
      });

      var backwardLaneCounter = {};
      var layoutBoxes = [];
      var layoutIds = Object.keys(layout.positions || {});
      for (var bi = 0; bi < layoutIds.length; bi += 1) {
        var bpos = layout.positions[layoutIds[bi]];
        if (bpos) {
          layoutBoxes.push({
            id: layoutIds[bi],
            left: bpos.left,
            right: bpos.right,
            top: bpos.top,
            bottom: bpos.bottom,
            cx: bpos.cx,
          });
        }
      }
      var globalRight = layoutBoxes.length
        ? Math.max.apply(null, layoutBoxes.map(function (x) { return x.right; }))
        : (layout.width - WORLD_PAD_X);
      var globalLeft = layoutBoxes.length
        ? Math.min.apply(null, layoutBoxes.map(function (x) { return x.left; }))
        : WORLD_PAD_X;

      function pickSafeHorizontalLane(src, dst, laneIndex, sourceId, targetId) {
        var isForward = dst.cx > src.cx + 16;
        var sy = src.cy + (outPortOffsetByEdge[edge.id] || 0);
        var ty = dst.cy + (inPortOffsetByEdge[edge.id] || 0);
        var elbowOut = 18 + (laneIndex * 6);
        var sx = isForward ? src.right : src.left;
        var tx = isForward ? dst.left : dst.right;
        var ex1 = isForward ? (sx + elbowOut) : (sx - elbowOut);
        var ex2 = isForward ? (tx - elbowOut) : (tx + elbowOut);
        if (isForward && ex2 < ex1 + 8) {
          var fmid = Math.round((sx + tx) / 2);
          ex1 = fmid - 4;
          ex2 = fmid + 4;
        }
        if (!isForward && ex1 < ex2 + 8) {
          var bmid = Math.round((sx + tx) / 2);
          ex1 = bmid + 4;
          ex2 = bmid - 4;
        }

        function segmentHitsBox(x1, y1, x2, y2, box, pad) {
          pad = normalizeNumber(pad, 4);
          var bl = box.left - pad;
          var br = box.right + pad;
          var bt = box.top - pad;
          var bb = box.bottom + pad;
          if (Math.abs(y1 - y2) < 0.0001) {
            var yy = y1;
            var sx1 = Math.min(x1, x2);
            var sx2 = Math.max(x1, x2);
            return yy >= bt && yy <= bb && overlap(sx1, sx2, bl, br);
          }
          if (Math.abs(x1 - x2) < 0.0001) {
            var xx = x1;
            var sy1 = Math.min(y1, y2);
            var sy2 = Math.max(y1, y2);
            return xx >= bl && xx <= br && overlap(sy1, sy2, bt, bb);
          }
          return false;
        }

        function pathIsSafe(laneY) {
          var segments = [
            [sx, sy, ex1, sy],
            [ex1, sy, ex1, laneY],
            [ex1, laneY, ex2, laneY],
            [ex2, laneY, ex2, ty],
            [ex2, ty, tx, ty],
          ];
          for (var ri = 0; ri < layoutBoxes.length; ri += 1) {
            var box = layoutBoxes[ri];
            if ((box.id === sourceId) || (box.id === targetId)) continue;
            for (var si = 0; si < segments.length; si += 1) {
              var s = segments[si];
              if (segmentHitsBox(s[0], s[1], s[2], s[3], box, 4)) return false;
            }
          }
          return true;
        }

        var baseGap = 26 + (laneIndex * 12);
        var baseBelow = Math.max(src.bottom, dst.bottom) + baseGap;
        var baseAbove = Math.min(src.top, dst.top) - baseGap;
        var candidates = [];
        for (var i = 0; i < 8; i += 1) {
          var step = i * 16;
          candidates.push(baseBelow + step);
          candidates.push(baseAbove - step);
        }
        for (var ci = 0; ci < candidates.length; ci += 1) {
          var laneY = Math.max(WORLD_PAD_Y, Math.min(layout.height - WORLD_PAD_Y, candidates[ci]));
          if (pathIsSafe(laneY)) return laneY;
        }
        return Math.max(WORLD_PAD_Y, Math.min(layout.height - WORLD_PAD_Y, baseBelow));
      }

      function pickSafeVerticalSide(src, dst, laneIndex, sourceId, targetId) {
        var y1 = Math.min(src.cy, dst.cy);
        var y2 = Math.max(src.cy, dst.cy);
        var rightMost = globalRight;
        var leftMost = globalLeft;
        for (var ri = 0; ri < layoutBoxes.length; ri += 1) {
          var box = layoutBoxes[ri];
          if ((box.id === sourceId) || (box.id === targetId)) continue;
          if (!overlap(y1 - 10, y2 + 10, box.top, box.bottom)) continue;
          rightMost = Math.max(rightMost, box.right);
          leftMost = Math.min(leftMost, box.left);
        }
        var rightX = rightMost + 20 + (laneIndex * 12);
        var leftX = leftMost - 20 - (laneIndex * 12);
        var preferRight = dst.cx >= src.cx;
        if (preferRight && rightX <= (layout.width - WORLD_PAD_X)) return rightX;
        if (!preferRight && leftX >= WORLD_PAD_X) return leftX;
        if (rightX <= (layout.width - WORLD_PAD_X)) return rightX;
        if (leftX >= WORLD_PAD_X) return leftX;
        return Math.max(WORLD_PAD_X, Math.min(layout.width - WORLD_PAD_X, preferRight ? rightX : leftX));
      }

      function hasCorridorObstacle(src, dst, sourceId, targetId) {
        var x1 = Math.min(src.right, dst.left);
        var x2 = Math.max(src.right, dst.left);
        var y1 = Math.min(src.top, dst.top) - 14;
        var y2 = Math.max(src.bottom, dst.bottom) + 14;
        for (var ri = 0; ri < layoutBoxes.length; ri += 1) {
          var box = layoutBoxes[ri];
          if ((box.id === sourceId) || (box.id === targetId)) continue;
          if (overlap(x1, x2, box.left, box.right) && overlap(y1, y2, box.top, box.bottom)) return true;
        }
        return false;
      }

      for (var e = 0; e < links.length; e += 1) {
        var edge = links[e];
        var src = layout.positions[edge.source];
        var dst = layout.positions[edge.target];
        if (!src || !dst) continue;
        var backwardLike = dst.cx <= src.cx + 16;
        var laneIndex = 0;
        if (backwardLike) {
          var bucket = Math.round(Math.min(src.cx, dst.cx) / 90) + "|" + Math.round(Math.max(src.cx, dst.cx) / 90);
          var laneKey = (dst.cx < src.cx - 16 ? "back" : "vert") + "|" + bucket;
          backwardLaneCounter[laneKey] = (backwardLaneCounter[laneKey] || 0) + 1;
          laneIndex = backwardLaneCounter[laneKey] - 1;
        }
        var safeLaneY = NaN;
        var safeSideX = NaN;
        if (dst.cx < src.cx - 16) {
          safeLaneY = pickSafeHorizontalLane(src, dst, laneIndex, edge.source, edge.target);
        } else if (dst.cx > src.cx + 16) {
          if (hasCorridorObstacle(src, dst, edge.source, edge.target)) {
            safeLaneY = pickSafeHorizontalLane(src, dst, laneIndex, edge.source, edge.target);
          }
        } else if (dst.cx <= src.cx + 16) {
          safeSideX = pickSafeVerticalSide(src, dst, laneIndex, edge.source, edge.target);
        }
        var d = edgePath(
          src,
          dst,
          {
            syOffset: outPortOffsetByEdge[edge.id] || 0,
            tyOffset: inPortOffsetByEdge[edge.id] || 0,
            laneIndex: laneIndex,
            safeLaneY: safeLaneY,
            safeSideX: safeSideX,
          },
          layout.height
        );
        if (!d) continue;

        var active = !!state.activeEdgeSet[edge.id];
        var hidden = state.criticalOnly && !active;
        var edgeClass =
          "abuse-edge " +
          relationClass(edge.relation) +
          (edge.synthetic ? " is-synthetic" : "") +
          (active ? "" : " is-inactive") +
          (hidden ? " is-hidden" : "") +
          ((critical.edges || {})[edge.id] ? " is-critical" : "");
        var visibleWidth = Math.max(1.2, Math.min(3.0, 1.1 + (edge.weight * 0.38)));

        var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", d);
        path.setAttribute("class", edgeClass);
        path.setAttribute("stroke-width", String(visibleWidth));
        path.setAttribute("pointer-events", "none");
        svg.appendChild(path);

      }

      for (var i = 0; i < nodes.length; i += 1) {
        var node = nodes[i];
        var pos = layout.positions[node.id];
        if (!pos) continue;
        var nodeActive = !!state.activeNodeSet[node.id];
        var nodeHidden = state.criticalOnly && !nodeActive;
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className =
          "abuse-node" +
          (node.id === state.selectedNodeId ? " is-selected" : "") +
          (nodeActive ? "" : " is-inactive") +
          (nodeHidden ? " is-hidden" : "") +
          ((critical.nodes || {})[node.id] ? " is-critical" : "");
        btn.style.left = String(pos.cx) + "px";
        btn.style.top = String(pos.cy) + "px";
        btn.style.width = String(pos.w) + "px";
        var tags = (node.tags || []).map(function (t) {
          return '<span class="abuse-node-tag">' + esc(t) + "</span>";
        }).join("");
        var detail = esc(node.detail || "");
        var detailHtml = detail ? ('<p class="abuse-node-detail">' + detail + "</p>") : "";
        btn.innerHTML =
          '<div class="abuse-node-head"><span class="abuse-node-kind"><i data-lucide="' + esc(node.icon) + '"></i>' + esc(node.kind) + "</span></div>" +
          '<p class="abuse-node-title">' + esc(node.title) + "</p>" +
          detailHtml +
          '<div class="abuse-node-tags">' + tags + "</div>";
        btn.addEventListener("click", (function (nodeId) {
          return function () {
            state.selectedNodeId = nodeId;
            refresh();
          };
        })(node.id));
        nodeLayer.appendChild(btn);
      }

      if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
      applyPanTransform();
    }

    function refresh() {
      computeActiveSets();
      renderGraph();
      renderDetails();
    }

    if (criticalToggle) {
      criticalToggle.checked = false;
      criticalToggle.addEventListener("change", function () {
        state.criticalOnly = !!criticalToggle.checked;
        refresh();
      });
    }

    function beginPan(ev) {
      if (!ev || ev.button !== 0) return;
      var target = ev.target;
      if (target && target.closest && target.closest(".abuse-node")) return;
      state.isPanning = true;
      state.panStartX = ev.clientX;
      state.panStartY = ev.clientY;
      state.panOriginX = state.panX;
      state.panOriginY = state.panY;
      canvas.classList.add("is-panning");
      if (document && document.body) document.body.style.userSelect = "none";
      if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
    }

    function movePan(ev) {
      if (!state.isPanning) return;
      var dx = ev.clientX - state.panStartX;
      var dy = ev.clientY - state.panStartY;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) state.suppressNextClick = true;
      var next = clampPan(state.panOriginX + dx, state.panOriginY + dy);
      state.panX = next.x;
      state.panY = next.y;
      applyPanTransform();
      if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
    }

    function endPan() {
      if (!state.isPanning) return;
      state.isPanning = false;
      canvas.classList.remove("is-panning");
      if (document && document.body) document.body.style.userSelect = "";
      if (state.suppressNextClick) {
        window.setTimeout(function () { state.suppressNextClick = false; }, 0);
      }
    }

    canvas.addEventListener("mousedown", beginPan);
    window.addEventListener("mousemove", movePan);
    window.addEventListener("mouseup", endPan);
    canvas.addEventListener("mouseleave", endPan);

    canvas.addEventListener("click", function (ev) {
      if (state.suppressNextClick) {
        state.suppressNextClick = false;
        return;
      }
      if (ev.target === canvas || ev.target === svg) {
        state.selectedNodeId = "";
        refresh();
      }
    });

    var redrawTimer = null;
    function queueRefresh() {
      if (redrawTimer) window.clearTimeout(redrawTimer);
      redrawTimer = window.setTimeout(function () {
        redrawTimer = null;
        refresh();
      }, 120);
    }
    window.addEventListener("resize", queueRefresh);
    if (window.ResizeObserver) {
      var ro = new ResizeObserver(queueRefresh);
      ro.observe(canvas);
    }

    refresh();
  };
})();
