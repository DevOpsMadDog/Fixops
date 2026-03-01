/**
 * AttackPathGraph — Interactive SVG-based attack path visualization.
 *
 * Renders a force-directed-style graph showing nodes (assets, vulns, services)
 * connected by edges (attack paths). Supports:
 *   - Click-to-select node with detail sidebar
 *   - Colour-coded by risk/severity (red=critical, orange=high, yellow=medium, green=low)
 *   - Animated pulse on active threats
 *   - Zoom/pan via mouse wheel + drag
 *   - Path highlighting on hover
 */

import { useState, useRef, useCallback, useMemo } from 'react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GraphNode {
  id: string;
  label: string;
  type: 'asset' | 'vulnerability' | 'service' | 'entry_point' | 'target' | 'hop';
  risk_score: number;   // 0-100
  metadata?: Record<string, unknown>;
  // layout (set internally)
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  risk_score?: number;
  type?: 'lateral' | 'exploit' | 'escalation' | 'exfiltration';
}

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNodeId?: string | null;
  onNodeSelect?: (nodeId: string | null) => void;
  width?: number;
  height?: number;
  className?: string;
}

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

function riskColor(score: number): string {
  if (score >= 90) return '#ef4444'; // red-500
  if (score >= 70) return '#f97316'; // orange-500
  if (score >= 40) return '#eab308'; // yellow-500
  if (score >= 20) return '#22c55e'; // green-500
  return '#6b7280';                   // gray-500
}

function typeIcon(type: GraphNode['type']): string {
  switch (type) {
    case 'entry_point': return '⬤';
    case 'target': return '◉';
    case 'vulnerability': return '⚠';
    case 'service': return '◆';
    case 'asset': return '■';
    default: return '●';
  }
}

function typeRadius(type: GraphNode['type']): number {
  switch (type) {
    case 'entry_point': return 22;
    case 'target': return 22;
    case 'vulnerability': return 18;
    default: return 16;
  }
}

// ---------------------------------------------------------------------------
// Layout: simple force-directed circle layout for determinism
// ---------------------------------------------------------------------------

function layoutNodes(nodes: GraphNode[], w: number, h: number): GraphNode[] {
  if (nodes.length === 0) return [];

  const cx = w / 2;
  const cy = h / 2;
  const radius = Math.min(w, h) * 0.35;

  return nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    return {
      ...node,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    };
  });
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AttackPathGraph({
  nodes: rawNodes,
  edges,
  selectedNodeId,
  onNodeSelect,
  width = 800,
  height = 500,
  className = '',
}: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: width, h: height });
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef({ x: 0, y: 0 });

  // Layout nodes in a circle
  const nodes = useMemo(() => layoutNodes(rawNodes, width, height), [rawNodes, width, height]);

  // Build id→node map
  const nodeMap = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  // Edges connected to hovered node (for highlighting paths)
  const activeEdges = useMemo(() => {
    if (!hoveredNode) return new Set<string>();
    return new Set(
      edges
        .filter(e => e.source === hoveredNode || e.target === hoveredNode)
        .map(e => e.id),
    );
  }, [hoveredNode, edges]);

  // ---------- Pan / Zoom ----------
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY > 0 ? 1.1 : 0.9;
    setViewBox(prev => {
      const newW = prev.w * zoomFactor;
      const newH = prev.h * zoomFactor;
      // Zoom towards centre
      return {
        x: prev.x + (prev.w - newW) / 2,
        y: prev.y + (prev.h - newH) / 2,
        w: newW,
        h: newH,
      };
    });
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0 && e.target === svgRef.current) {
      setIsPanning(true);
      panStart.current = { x: e.clientX, y: e.clientY };
    }
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanning) return;
    const dx = e.clientX - panStart.current.x;
    const dy = e.clientY - panStart.current.y;
    panStart.current = { x: e.clientX, y: e.clientY };
    const scale = viewBox.w / width;
    setViewBox(prev => ({
      ...prev,
      x: prev.x - dx * scale,
      y: prev.y - dy * scale,
    }));
  }, [isPanning, viewBox.w, width]);

  const handleMouseUp = useCallback(() => setIsPanning(false), []);

  // ---------- Render ----------

  if (nodes.length === 0) {
    return (
      <div className={`flex items-center justify-center h-64 rounded-lg border border-dashed border-border bg-background/50 ${className}`}>
        <p className="text-muted-foreground">No graph data available. Run an analysis first.</p>
      </div>
    );
  }

  return (
    <div className={`relative rounded-lg border border-border bg-background/30 overflow-hidden ${className}`}>
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
        className="cursor-grab active:cursor-grabbing"
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <defs>
          {/* Arrowhead marker */}
          <marker
            id="arrowhead"
            markerWidth="10"
            markerHeight="7"
            refX="9"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#6b7280" opacity="0.6" />
          </marker>
          <marker
            id="arrowhead-active"
            markerWidth="10"
            markerHeight="7"
            refX="9"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" opacity="0.8" />
          </marker>
          {/* Glow filter */}
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {edges.map(edge => {
          const src = nodeMap.get(edge.source);
          const tgt = nodeMap.get(edge.target);
          if (!src || !tgt || src.x == null || src.y == null || tgt.x == null || tgt.y == null) return null;

          const isActive = activeEdges.has(edge.id) || hoveredEdge === edge.id;
          const isSelected = selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId);

          return (
            <g key={edge.id}>
              <line
                x1={src.x}
                y1={src.y}
                x2={tgt.x}
                y2={tgt.y}
                stroke={isActive || isSelected ? '#ef4444' : '#4b5563'}
                strokeWidth={isActive || isSelected ? 2.5 : 1.5}
                strokeDasharray={edge.type === 'lateral' ? '6,3' : undefined}
                opacity={isActive || isSelected ? 0.9 : 0.3}
                markerEnd={isActive ? 'url(#arrowhead-active)' : 'url(#arrowhead)'}
                className="transition-all duration-200"
                onMouseEnter={() => setHoveredEdge(edge.id)}
                onMouseLeave={() => setHoveredEdge(null)}
                style={{ cursor: 'pointer' }}
              />
              {/* Edge label */}
              {(isActive || isSelected) && edge.label && (
                <text
                  x={(src.x + tgt.x) / 2}
                  y={(src.y + tgt.y) / 2 - 8}
                  textAnchor="middle"
                  fill="#9ca3af"
                  fontSize="10"
                  className="pointer-events-none select-none"
                >
                  {edge.label}
                </text>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map(node => {
          if (node.x == null || node.y == null) return null;
          const r = typeRadius(node.type);
          const color = riskColor(node.risk_score);
          const isSelected = selectedNodeId === node.id;
          const isHovered = hoveredNode === node.id;

          return (
            <g
              key={node.id}
              className="cursor-pointer"
              onClick={() => onNodeSelect?.(isSelected ? null : node.id)}
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
            >
              {/* Pulse ring for critical */}
              {node.risk_score >= 90 && (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r + 6}
                  fill="none"
                  stroke={color}
                  strokeWidth="1.5"
                  opacity="0.4"
                >
                  <animate
                    attributeName="r"
                    values={`${r + 4};${r + 12};${r + 4}`}
                    dur="2s"
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    values="0.4;0.1;0.4"
                    dur="2s"
                    repeatCount="indefinite"
                  />
                </circle>
              )}

              {/* Selection ring */}
              {(isSelected || isHovered) && (
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r + 4}
                  fill="none"
                  stroke={color}
                  strokeWidth="2"
                  opacity="0.7"
                  filter={isSelected ? 'url(#glow)' : undefined}
                />
              )}

              {/* Node circle */}
              <circle
                cx={node.x}
                cy={node.y}
                r={r}
                fill={`${color}20`}
                stroke={color}
                strokeWidth={isSelected ? 3 : 2}
                className="transition-all duration-200"
              />

              {/* Type icon */}
              <text
                x={node.x}
                y={node.y + 1}
                textAnchor="middle"
                dominantBaseline="middle"
                fill={color}
                fontSize={r * 0.7}
                className="pointer-events-none select-none"
              >
                {typeIcon(node.type)}
              </text>

              {/* Label */}
              <text
                x={node.x}
                y={node.y + r + 14}
                textAnchor="middle"
                fill="#d1d5db"
                fontSize="11"
                fontWeight={isSelected ? 'bold' : 'normal'}
                className="pointer-events-none select-none"
              >
                {node.label.length > 18 ? node.label.slice(0, 16) + '…' : node.label}
              </text>

              {/* Risk badge */}
              <text
                x={node.x}
                y={node.y - r - 6}
                textAnchor="middle"
                fill={color}
                fontSize="10"
                fontWeight="bold"
                className="pointer-events-none select-none"
              >
                {node.risk_score}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-2 left-2 flex gap-3 text-xs text-muted-foreground bg-background/80 backdrop-blur rounded px-2 py-1">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Critical</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> High</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Medium</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" /> Low</span>
      </div>

      {/* Zoom controls */}
      <div className="absolute top-2 right-2 flex flex-col gap-1">
        <button
          onClick={() => setViewBox(prev => ({
            x: prev.x + prev.w * 0.05,
            y: prev.y + prev.h * 0.05,
            w: prev.w * 0.9,
            h: prev.h * 0.9,
          }))}
          className="w-7 h-7 rounded bg-background/80 backdrop-blur border border-border text-foreground text-sm hover:bg-muted flex items-center justify-center"
        >
          +
        </button>
        <button
          onClick={() => setViewBox(prev => ({
            x: prev.x - prev.w * 0.05,
            y: prev.y - prev.h * 0.05,
            w: prev.w * 1.1,
            h: prev.h * 1.1,
          }))}
          className="w-7 h-7 rounded bg-background/80 backdrop-blur border border-border text-foreground text-sm hover:bg-muted flex items-center justify-center"
        >
          −
        </button>
        <button
          onClick={() => setViewBox({ x: 0, y: 0, w: width, h: height })}
          className="w-7 h-7 rounded bg-background/80 backdrop-blur border border-border text-foreground text-xs hover:bg-muted flex items-center justify-center"
          title="Reset zoom"
        >
          ⟲
        </button>
      </div>
    </div>
  );
}
