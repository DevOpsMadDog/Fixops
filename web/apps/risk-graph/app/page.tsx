'use client'

import { useState, useMemo, useRef, useEffect, useCallback } from 'react'
import dynamic from 'next/dynamic'
import { AppShell } from '@fixops/ui'
import { AlertCircle, Shield, Code, XCircle, Filter, Search, Layers, ArrowLeft, Loader2 } from 'lucide-react'
import { useGraph, useSystemMode, useDemoMode } from '@fixops/api-client'
import { Switch, StatusBadge, StatCard, Surface } from '@fixops/ui'

const CytoscapeComponent = dynamic(
  () => import('react-cytoscapejs'),
  { ssr: false }
)

interface GraphNodeData {
  id: string
  label: string
  type: string
  severity?: string
  kev?: boolean
  epss?: number
  internet_facing?: boolean
}

interface GraphEdgeData {
  source: string
  target: string
}

const DEMO_GRAPH_DATA: { nodes: { data: GraphNodeData }[]; edges: { data: GraphEdgeData }[] } = {
  nodes: [
    { data: { id: 's1', label: 'payment-api', type: 'service', severity: 'critical', internet_facing: true } },
    { data: { id: 's2', label: 'user-service', type: 'service', severity: 'high', internet_facing: true } },
    { data: { id: 's3', label: 'auth-service', type: 'service', severity: 'medium', internet_facing: true } },
    { data: { id: 's4', label: 'logging-service', type: 'service', severity: 'critical', internet_facing: true } },
    
    { data: { id: 'c1', label: 'struts-core@2.5.30', type: 'component', severity: 'critical' } },
    { data: { id: 'c2', label: 'openssl@1.1.1k', type: 'component', severity: 'high' } },
    { data: { id: 'c3', label: 'log4j@2.14.1', type: 'component', severity: 'critical' } },
    { data: { id: 'c4', label: 'express@4.17.1', type: 'component', severity: 'medium' } },
    { data: { id: 'c5', label: 'react@17.0.2', type: 'component', severity: 'low' } },
    
    { data: { id: 'cve1', label: 'CVE-2023-50164', type: 'cve', severity: 'critical', kev: true, epss: 0.89 } },
    { data: { id: 'cve2', label: 'CVE-2023-4807', type: 'cve', severity: 'high', kev: true, epss: 0.72 } },
    { data: { id: 'cve3', label: 'CVE-2021-44228', type: 'cve', severity: 'critical', kev: true, epss: 0.95 } },
    { data: { id: 'cve4', label: 'CVE-2023-26136', type: 'cve', severity: 'medium', kev: false, epss: 0.23 } },
    
    { data: { id: 'sast1', label: 'SQL Injection', type: 'sast', severity: 'high' } },
    { data: { id: 'sast2', label: 'XSS Vulnerability', type: 'sast', severity: 'medium' } },
  ],
  edges: [
    { data: { source: 's1', target: 'c1' } },
    { data: { source: 's1', target: 'c2' } },
    { data: { source: 's2', target: 'c4' } },
    { data: { source: 's2', target: 'c5' } },
    { data: { source: 's3', target: 'c2' } },
    { data: { source: 's4', target: 'c3' } },
    
    { data: { source: 'c1', target: 'cve1' } },
    { data: { source: 'c2', target: 'cve2' } },
    { data: { source: 'c3', target: 'cve3' } },
    { data: { source: 'c4', target: 'cve4' } },
    
    { data: { source: 's2', target: 'sast1' } },
    { data: { source: 's2', target: 'sast2' } },
  ],
}

interface GraphNode {
  data: {
    id: string
    label: string
    type: string
    severity?: string
    kev?: boolean
  }
}

interface SelectedNodeData {
  id: string
  label: string
  type: string
  severity?: string
  kev?: boolean
  epss?: number
  internet_facing?: boolean
  business_criticality?: string
  data_classification?: string[]
}

export default function RiskGraphPage() {
  const { data: graphApiData, loading: apiLoading, error: apiError } = useGraph()
  const { mode } = useSystemMode()
  const { demoEnabled, toggleDemoMode } = useDemoMode()

  const transformApiData = useCallback((apiData: NonNullable<typeof graphApiData>): typeof DEMO_GRAPH_DATA => {
    const nodes = apiData.nodes.map(node => ({
      data: {
        id: node.id,
        label: node.label,
        type: node.type,
        severity: node.severity,
        kev: node.kev,
        epss: node.epss,
        internet_facing: node.internet_facing,
      }
    }))

    const edges = apiData.edges.map(edge => ({
      data: {
        source: edge.source,
        target: edge.target,
      }
    }))

    return { nodes, edges }
  }, [])

  // Demo mode: explicitly show demo data when toggle is ON
  // Live mode: show real API data (or empty state if no data)
  const hasApiData = graphApiData?.nodes && graphApiData.nodes.length > 0
  const currentGraphData = useMemo(() => {
    if (demoEnabled) {
      return DEMO_GRAPH_DATA
    }
    if (hasApiData) {
      return transformApiData(graphApiData)
    }
    return { nodes: [], edges: [] } // Empty state when no API data and demo mode is OFF
  }, [graphApiData, transformApiData, demoEnabled, hasApiData])

  const [selectedNode, setSelectedNode] = useState<SelectedNodeData | null>(null)
  const [filters, setFilters] = useState({
    kev_only: false,
    internet_facing: false,
    show_sast: true,
    show_cve: true,
    min_severity: 'low',
    min_epss: 0,
  })
  const [searchQuery, setSearchQuery] = useState('')
  const cyRef = useRef<any>(null)

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#f59e0b',
      low: '#3b82f6',
    }
    return colors[severity as keyof typeof colors] || colors.low
  }

  const getNodeColor = (node: GraphNode['data']) => {
    if (node.type === 'service') return '#6B5AED'
    if (node.type === 'component') return '#10b981'
    return getSeverityColor(node.severity || 'low')
  }

  const getNodeSize = (node: GraphNode['data']) => {
    if (node.type === 'service') return 60
    if (node.type === 'component') return 50
    if (node.severity === 'critical') return 45
    if (node.severity === 'high') return 40
    return 35
  }

  const cytoscapeStylesheet = [
    {
      selector: 'node',
      style: {
        'background-color': (ele: any) => getNodeColor(ele.data() as GraphNode['data']),
        'label': 'data(label)',
        'color': '#ffffff',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'font-weight': 'bold',
        'width': (ele: any) => getNodeSize(ele.data() as GraphNode['data']),
        'height': (ele: any) => getNodeSize(ele.data() as GraphNode['data']),
        'border-width': (ele: any) => (ele.data() as GraphNode['data']).kev ? 3 : 0,
        'border-color': '#fbbf24',
        'text-wrap': 'wrap',
        'text-max-width': '80px',
      },
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#334155',
        'target-arrow-color': '#334155',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
      },
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 3,
        'border-color': '#6B5AED',
      },
    },
  ]

  const layout = {
    name: 'cose',
    animate: true,
    animationDuration: 500,
    nodeRepulsion: 8000,
    idealEdgeLength: 100,
    edgeElasticity: 100,
    nestingFactor: 1.2,
    gravity: 1,
    numIter: 1000,
    initialTemp: 200,
    coolingFactor: 0.95,
    minTemp: 1.0,
  }

  const handleNodeClick = (event: any) => {
    const node = event.target
    setSelectedNode(node.data() as SelectedNodeData)
  }

  const graphData = useMemo(() => {
    let filteredNodes = [...currentGraphData.nodes]
    let filteredEdges = [...currentGraphData.edges]

    if (filters.kev_only) {
      const kevNodeIds = filteredNodes
        .filter(n => n.data.kev)
        .map(n => n.data.id)
      
      filteredNodes = filteredNodes.filter(n => {
        if (n.data.kev) return true
        const hasKevConnection = filteredEdges.some(e => 
          (e.data.source === n.data.id && kevNodeIds.includes(e.data.target)) ||
          (e.data.target === n.data.id && kevNodeIds.includes(e.data.source))
        )
        return hasKevConnection
      })
    }

    if (filters.internet_facing) {
      const internetFacingIds = filteredNodes
        .filter(n => n.data.internet_facing)
        .map(n => n.data.id)
      
      filteredNodes = filteredNodes.filter(n => {
        if (n.data.internet_facing) return true
        const hasInternetConnection = filteredEdges.some(e => 
          (e.data.source === n.data.id && internetFacingIds.includes(e.data.target)) ||
          (e.data.target === n.data.id && internetFacingIds.includes(e.data.source))
        )
        return hasInternetConnection
      })
    }

    if (!filters.show_sast) {
      filteredNodes = filteredNodes.filter(n => n.data.type !== 'sast')
    }

    if (!filters.show_cve) {
      filteredNodes = filteredNodes.filter(n => n.data.type !== 'cve')
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filteredNodes = filteredNodes.filter(n => 
        n.data.label?.toLowerCase().includes(query)
      )
    }

    const nodeIds = new Set(filteredNodes.map(n => n.data.id))
    filteredEdges = filteredEdges.filter(e => 
      nodeIds.has(e.data.source) && nodeIds.has(e.data.target)
    )

    return {
      nodes: filteredNodes,
      edges: filteredEdges,
    }
  }, [filters, searchQuery, currentGraphData])

  const summary = useMemo(() => ({
    services: currentGraphData.nodes.filter(n => n.data.type === 'service').length,
    components: currentGraphData.nodes.filter(n => n.data.type === 'component').length,
    issues: currentGraphData.nodes.filter(n => n.data.type === 'cve' || n.data.type === 'sast').length,
    kev: currentGraphData.nodes.filter(n => n.data.kev).length,
  }), [currentGraphData])

  return (
    <AppShell activeApp="risk">
    <div className="flex min-h-screen bg-[#0f172a] font-sans text-white">
      {/* Left Sidebar - Filters */}
      <div className="w-72 bg-white/[0.02] backdrop-blur-xl border-r border-white/[0.06] flex flex-col sticky top-0 h-screen">
        {/* Header */}
        <div className="p-5 border-b border-white/[0.06]">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#6B5AED] to-[#8B7CF7] flex items-center justify-center shadow-[0_0_20px_rgba(107,90,237,0.3)]">
                <Layers size={16} className="text-white" />
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-white tracking-tight">Risk Graph</h2>
                <p className="text-[11px] text-slate-500">Interactive visualization</p>
              </div>
            </div>
            <button
              onClick={() => window.location.href = '/triage'}
              className="p-2 rounded-xl bg-white/[0.04] ring-1 ring-white/[0.08] text-slate-400 hover:bg-white/[0.08] hover:text-white transition-all"
              title="Switch to Triage View"
            >
              <ArrowLeft size={16} />
            </button>
          </div>
          
          {/* Demo Mode Toggle - Apple-like */}
          <div className="mt-4 p-3 rounded-xl bg-white/[0.03] ring-1 ring-white/[0.06]">
            <Switch
              checked={demoEnabled}
              onChange={toggleDemoMode}
              label={demoEnabled ? 'Demo Mode' : 'Live Mode'}
              size="sm"
            />
            {/* Status Badge */}
            <div className="mt-2">
              {apiLoading && !demoEnabled && (
                <StatusBadge status="loading" label="Loading..." />
              )}
              {apiError && !apiLoading && !demoEnabled && (
                <StatusBadge status="error" label="API Error" />
              )}
              {!apiLoading && !apiError && !hasApiData && !demoEnabled && (
                <StatusBadge status="warning" label="No Data" />
              )}
              {demoEnabled && (
                <StatusBadge status="demo" label="Demo Data" />
              )}
              {!demoEnabled && hasApiData && !apiLoading && !apiError && (
                <StatusBadge status="live" label={`Live (${mode})`} />
              )}
            </div>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="p-4 border-b border-white/[0.06]">
          <div className="grid grid-cols-2 gap-2">
            <StatCard label="Services" value={summary.services} color="purple" />
            <StatCard label="Components" value={summary.components} color="green" />
            <StatCard label="Issues" value={summary.issues} color="red" />
            <StatCard label="KEV" value={summary.kev} color="amber" />
          </div>
        </div>

        {/* Search */}
        <div className="p-4 border-b border-white/10">
          <div className="relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search nodes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full py-2 pl-10 pr-3 bg-white/5 border border-white/10 rounded-md text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#6B5AED]/50"
            />
          </div>
        </div>

        {/* Filters */}
        <div className="p-4 flex-1 overflow-auto">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
            <Filter size={12} className="inline mr-1" />
            Filters
          </div>

          {/* Toggle Filters */}
          <div className="space-y-2 mb-4">
            <label className="flex items-center justify-between p-2 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
              <span className="text-sm text-slate-300">KEV Only</span>
              <input
                type="checkbox"
                checked={filters.kev_only}
                onChange={(e) => setFilters({ ...filters, kev_only: e.target.checked })}
                className="cursor-pointer"
              />
            </label>
            <label className="flex items-center justify-between p-2 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
              <span className="text-sm text-slate-300">Internet-Facing Only</span>
              <input
                type="checkbox"
                checked={filters.internet_facing}
                onChange={(e) => setFilters({ ...filters, internet_facing: e.target.checked })}
                className="cursor-pointer"
              />
            </label>
          </div>

          {/* Node Type Filters */}
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 mt-4">
            <Layers size={12} className="inline mr-1" />
            Node Types
          </div>
          <div className="space-y-2 mb-4">
            <label className="flex items-center justify-between p-2 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
              <span className="text-sm text-slate-300">Show CVEs</span>
              <input
                type="checkbox"
                checked={filters.show_cve}
                onChange={(e) => setFilters({ ...filters, show_cve: e.target.checked })}
                className="cursor-pointer"
              />
            </label>
            <label className="flex items-center justify-between p-2 bg-white/5 rounded-md cursor-pointer hover:bg-white/10 transition-all">
              <span className="text-sm text-slate-300">Show SAST Findings</span>
              <input
                type="checkbox"
                checked={filters.show_sast}
                onChange={(e) => setFilters({ ...filters, show_sast: e.target.checked })}
                className="cursor-pointer"
              />
            </label>
          </div>

          {/* Legend */}
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-3 mt-4">
            Legend
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-4 h-4 rounded-full bg-[#6B5AED]"></div>
              <span>Service</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-4 h-4 rounded-full bg-green-500"></div>
              <span>Component</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-4 h-4 rounded-full bg-red-500"></div>
              <span>Critical Issue</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-4 h-4 rounded-full bg-orange-500"></div>
              <span>High Issue</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-4 h-4 rounded-full bg-amber-500 border-2 border-amber-400"></div>
              <span>KEV (gold border)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Graph Area */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <div className="p-5 border-b border-white/10 bg-[#0f172a]/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold mb-1">Security Risk Graph</h1>
              <p className="text-sm text-slate-500">
                Showing {graphData.nodes.length} nodes • {graphData.edges.length} relationships
              </p>
            </div>
            <button
              onClick={() => window.location.href = '/triage'}
              className="px-4 py-2 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md text-[#6B5AED] text-sm font-medium hover:bg-[#6B5AED]/20 transition-all"
            >
              Triage View
            </button>
          </div>
        </div>

        {/* Graph Canvas */}
        <div className="flex-1 relative bg-[#0a0f1e]">
          {typeof window !== 'undefined' && (
            <CytoscapeComponent
              elements={[...graphData.nodes, ...graphData.edges]}
              style={{ width: '100%', height: '100%' }}
              stylesheet={cytoscapeStylesheet}
              layout={layout}
              cy={(cy) => {
                cyRef.current = cy
                cy.on('tap', 'node', handleNodeClick)
              }}
            />
          )}
        </div>
      </div>

      {/* Node Detail Drawer */}
      {selectedNode && (
        <div
          onClick={() => setSelectedNode(null)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[500px] h-full bg-[#1e293b] border-l border-white/10 flex flex-col animate-slide-in"
          >
            {/* Drawer Header */}
            <div className="p-6 border-b border-white/10">
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2">
                  {selectedNode.type === 'service' && <Shield size={20} className="text-[#6B5AED]" />}
                  {selectedNode.type === 'component' && <Code size={20} className="text-green-500" />}
                  {(selectedNode.type === 'cve' || selectedNode.type === 'sast') && (
                    <AlertCircle size={20} style={{ color: getSeverityColor(selectedNode.severity || 'low') }} />
                  )}
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    {selectedNode.type}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <XCircle size={20} />
                </button>
              </div>
              <h3 className="text-lg font-semibold mb-2">{selectedNode.label}</h3>
              {selectedNode.severity && (
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: getSeverityColor(selectedNode.severity) }}
                  ></div>
                  <span
                    className="text-sm font-semibold capitalize"
                    style={{ color: getSeverityColor(selectedNode.severity) }}
                  >
                    {selectedNode.severity} Severity
                  </span>
                </div>
              )}
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-auto p-6">
              {/* Overview */}
              <div className="mb-6">
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Overview
                </h4>
                
                {selectedNode.type === 'service' && (
                  <div className="space-y-3">
                    <p className="text-sm text-slate-400">
                      Service node representing a deployed application or microservice.
                    </p>
                    {selectedNode.internet_facing && (
                      <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-md">
                        <div className="text-xs font-semibold text-amber-300 mb-1">
                          Internet-Facing
                        </div>
                        <div className="text-xs text-slate-300">
                          This service is exposed to the public internet and requires immediate attention for any vulnerabilities.
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {selectedNode.type === 'component' && (
                  <div className="space-y-3">
                    <p className="text-sm text-slate-400">
                      Software component or dependency used by one or more services.
                    </p>
                  </div>
                )}

                {(selectedNode.type === 'cve' || selectedNode.type === 'sast') && (
                  <div className="space-y-3">
                    <p className="text-sm text-slate-400">
                      {selectedNode.type === 'cve' 
                        ? 'Known vulnerability (CVE) affecting one or more components.'
                        : 'Security finding identified through static analysis (SAST).'}
                    </p>
                    
                    {selectedNode.kev && (
                      <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-md">
                        <div className="text-xs font-semibold text-red-300 mb-1">
                          Known Exploited Vulnerability (KEV)
                        </div>
                        <div className="text-xs text-slate-300">
                          This vulnerability is actively being exploited in the wild according to CISA KEV catalog.
                        </div>
                      </div>
                    )}

                    {selectedNode.epss && selectedNode.epss > 0 && (
                      <div className="p-3 bg-white/5 rounded-md">
                        <div className="text-xs font-semibold text-slate-300 mb-1">
                          EPSS Score
                        </div>
                        <div className="text-2xl font-bold text-[#6B5AED] mb-1">
                          {(selectedNode.epss * 100).toFixed(1)}%
                        </div>
                        <div className="text-xs text-slate-400">
                          Probability of exploitation in the next 30 days
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Actions */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Actions
                </h4>
                <div className="flex gap-2 flex-wrap">
                  <button
                    onClick={() => window.location.href = '/triage'}
                    className="px-3 py-2 bg-[#6B5AED]/10 border border-[#6B5AED]/30 rounded-md text-[#6B5AED] text-xs font-medium hover:bg-[#6B5AED]/20 transition-all"
                  >
                    View in Triage
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        @keyframes slide-in {
          from {
            transform: translateX(100%);
          }
          to {
            transform: translateX(0);
          }
        }
        .animate-slide-in {
          animation: slide-in 0.2s ease-out;
        }
      `}</style>
    </div>
    </AppShell>
  )
}
