import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import CytoscapeComponent from 'react-cytoscapejs'
import { X, Filter, AlertCircle, Shield, Globe, Database, List } from 'lucide-react'

const RiskGraph = () => {
  const navigate = useNavigate()
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] })
  const [selectedNode, setSelectedNode] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    kevOnly: false,
    minSeverity: 'low',
    showFindings: true,
    showCves: true,
    internetFacingOnly: false,
    minEpss: 0
  })
  const cyRef = useRef(null)

  useEffect(() => {
    loadGraphData()
  }, [])

  const loadGraphData = async () => {
    try {
      const apiBase = import.meta.env.VITE_FIXOPS_API_BASE
      const apiToken = import.meta.env.VITE_FIXOPS_API_TOKEN
      
      let url = '/demo/graph.json'
      let headers = {}
      
      if (apiBase) {
        url = `${apiBase}/api/v1/graph`
        if (apiToken) {
          headers['X-API-Key'] = apiToken
        }
      }
      
      const response = await fetch(url, { headers })
      const data = await response.json()
      setGraphData(data)
    } catch (error) {
      console.error('Failed to load graph:', error)
      try {
        const fallbackResponse = await fetch('/demo/graph.json')
        const fallbackData = await fallbackResponse.json()
        setGraphData(fallbackData)
      } catch (fallbackError) {
        console.error('Fallback also failed:', fallbackError)
      }
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#DC2626',
      high: '#EA580C',
      medium: '#F59E0B',
      low: '#3B82F6'
    }
    return colors[severity] || '#6B7280'
  }

  const getNodeColor = (node) => {
    if (node.type === 'service') {
      return node.internet_facing ? '#6B5AED' : '#8B5CF6'
    }
    if (node.type === 'component') {
      return node.internet_facing ? '#10B981' : '#14B8A6'
    }
    if (node.type === 'cve' || node.type === 'finding') {
      return getSeverityColor(node.severity)
    }
    return '#6B7280'
  }

  const getNodeSize = (node) => {
    if (node.type === 'service') return 60
    if (node.type === 'component') return 50
    if (node.severity === 'critical') return 45
    if (node.severity === 'high') return 40
    return 35
  }

  const filterNodes = (nodes) => {
    return nodes.filter(node => {
      if (filters.kevOnly && !node.kev) return false
      if (filters.internetFacingOnly && !node.internet_facing) return false
      if (node.epss < filters.minEpss) return false
      
      if (node.type === 'finding' && !filters.showFindings) return false
      if (node.type === 'cve' && !filters.showCves) return false
      
      if (node.severity) {
        const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 }
        const minLevel = severityOrder[filters.minSeverity] || 0
        const nodeLevel = severityOrder[node.severity] || 0
        if (nodeLevel < minLevel) return false
      }
      
      return true
    })
  }

  const filteredNodes = filterNodes(graphData.nodes || [])
  const filteredNodeIds = new Set(filteredNodes.map(n => n.id))
  const filteredEdges = (graphData.edges || []).filter(
    edge => filteredNodeIds.has(edge.source) && filteredNodeIds.has(edge.target)
  )

  const elements = [
    ...filteredNodes.map(node => ({
      data: {
        id: node.id,
        label: node.label,
        ...node
      },
      style: {
        'background-color': getNodeColor(node),
        'width': getNodeSize(node),
        'height': getNodeSize(node),
        'label': node.label,
        'color': '#FFFFFF',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'border-width': node.kev ? 3 : 1,
        'border-color': node.kev ? '#FCD34D' : '#FFFFFF',
        'border-opacity': node.kev ? 1 : 0.3
      }
    })),
    ...filteredEdges.map(edge => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: edge.type
      },
      style: {
        'width': 2,
        'line-color': '#374151',
        'target-arrow-color': '#374151',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 0.6
      }
    }))
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
    minTemp: 1.0
  }

  const handleNodeClick = (event) => {
    const node = event.target.data()
    setSelectedNode(node)
  }

  useEffect(() => {
    if (cyRef.current) {
      cyRef.current.on('tap', 'node', handleNodeClick)
      return () => {
        cyRef.current.removeAllListeners()
      }
    }
  }, [cyRef.current])

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#0F172A' }}>
        <div style={{ color: '#94A3B8', fontSize: '14px' }}>Loading risk graph...</div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#0F172A', color: '#E2E8F0' }}>
      <div style={{ flex: 1, position: 'relative' }}>
        <div style={{ position: 'absolute', top: '20px', right: '20px', zIndex: 11, display: 'flex', gap: '8px' }}>
          <button
            onClick={() => navigate('/triage')}
            style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', background: '#1E293B', border: '1px solid #334155', borderRadius: '6px', color: '#E2E8F0', fontSize: '14px', cursor: 'pointer', transition: 'all 0.2s' }}
            onMouseEnter={(e) => { e.target.style.background = '#334155' }}
            onMouseLeave={(e) => { e.target.style.background = '#1E293B' }}
          >
            <List size={16} />
            Triage View
          </button>
        </div>

        <div style={{ position: 'absolute', top: '20px', left: '20px', zIndex: 10, background: '#1E293B', padding: '16px', borderRadius: '8px', border: '1px solid #334155' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Filter size={16} color="#6B5AED" />
            <span style={{ fontSize: '14px', fontWeight: '600' }}>Filters</span>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={filters.kevOnly}
                onChange={(e) => setFilters({ ...filters, kevOnly: e.target.checked })}
                style={{ accentColor: '#6B5AED' }}
              />
              KEV Only
            </label>
            
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={filters.internetFacingOnly}
                onChange={(e) => setFilters({ ...filters, internetFacingOnly: e.target.checked })}
                style={{ accentColor: '#6B5AED' }}
              />
              Internet-Facing Only
            </label>
            
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={filters.showFindings}
                onChange={(e) => setFilters({ ...filters, showFindings: e.target.checked })}
                style={{ accentColor: '#6B5AED' }}
              />
              Show SAST Findings
            </label>
            
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={filters.showCves}
                onChange={(e) => setFilters({ ...filters, showCves: e.target.checked })}
                style={{ accentColor: '#6B5AED' }}
              />
              Show CVEs
            </label>
            
            <div>
              <label style={{ fontSize: '12px', display: 'block', marginBottom: '4px' }}>Min Severity</label>
              <select
                value={filters.minSeverity}
                onChange={(e) => setFilters({ ...filters, minSeverity: e.target.value })}
                style={{ width: '100%', padding: '4px 8px', background: '#0F172A', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0', fontSize: '12px' }}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            
            <div>
              <label style={{ fontSize: '12px', display: 'block', marginBottom: '4px' }}>Min EPSS: {filters.minEpss.toFixed(2)}</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={filters.minEpss}
                onChange={(e) => setFilters({ ...filters, minEpss: parseFloat(e.target.value) })}
                style={{ width: '100%', accentColor: '#6B5AED' }}
              />
            </div>
          </div>
        </div>

        <div style={{ position: 'absolute', top: '80px', right: '20px', zIndex: 10, background: '#1E293B', padding: '12px 16px', borderRadius: '8px', border: '1px solid #334155' }}>
          <div style={{ fontSize: '12px', color: '#94A3B8' }}>
            <div><strong>{filteredNodes.filter(n => n.type === 'service').length}</strong> Services</div>
            <div><strong>{filteredNodes.filter(n => n.type === 'component').length}</strong> Components</div>
            <div><strong>{filteredNodes.filter(n => n.type === 'cve' || n.type === 'finding').length}</strong> Issues</div>
            <div><strong>{filteredNodes.filter(n => n.kev).length}</strong> KEV</div>
          </div>
        </div>

        <CytoscapeComponent
          elements={elements}
          layout={layout}
          style={{ width: '100%', height: '100%' }}
          cy={(cy) => { cyRef.current = cy }}
          stylesheet={[
            {
              selector: 'node',
              style: {
                'label': 'data(label)',
                'text-valign': 'center',
                'text-halign': 'center',
                'font-size': '10px',
                'color': '#FFFFFF',
                'text-outline-width': 2,
                'text-outline-color': '#0F172A'
              }
            },
            {
              selector: 'edge',
              style: {
                'width': 2,
                'line-color': '#374151',
                'target-arrow-color': '#374151',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'opacity': 0.6
              }
            }
          ]}
        />
      </div>

      {selectedNode && (
        <div style={{ width: '400px', background: '#1E293B', borderLeft: '1px solid #334155', padding: '24px', overflowY: 'auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: '600', margin: 0 }}>{selectedNode.label}</h3>
            <button
              onClick={() => setSelectedNode(null)}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#94A3B8', padding: '4px' }}
            >
              <X size={20} />
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '4px' }}>Type</div>
              <div style={{ fontSize: '14px', textTransform: 'capitalize' }}>{selectedNode.type}</div>
            </div>

            {selectedNode.severity && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '4px' }}>Severity</div>
                <div style={{ display: 'inline-block', padding: '4px 12px', borderRadius: '4px', background: getSeverityColor(selectedNode.severity), fontSize: '12px', fontWeight: '600', textTransform: 'uppercase' }}>
                  {selectedNode.severity}
                </div>
              </div>
            )}

            {selectedNode.message && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '4px' }}>Description</div>
                <div style={{ fontSize: '14px', lineHeight: '1.5' }}>{selectedNode.message}</div>
              </div>
            )}

            {selectedNode.file && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '4px' }}>Location</div>
                <div style={{ fontSize: '12px', fontFamily: 'monospace', background: '#0F172A', padding: '8px', borderRadius: '4px' }}>
                  {selectedNode.file}
                </div>
              </div>
            )}

            {(selectedNode.type === 'cve' || selectedNode.type === 'finding') && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>Exploitability</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {selectedNode.kev && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#7C2D12', borderRadius: '4px' }}>
                      <AlertCircle size={16} color="#FCD34D" />
                      <span style={{ fontSize: '12px' }}>Known Exploited (KEV)</span>
                    </div>
                  )}
                  {selectedNode.epss > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#1E293B', border: '1px solid #334155', borderRadius: '4px' }}>
                      <Shield size={16} color="#6B5AED" />
                      <span style={{ fontSize: '12px' }}>EPSS: {(selectedNode.epss * 100).toFixed(1)}%</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {selectedNode.internet_facing !== undefined && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>Exposure</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: selectedNode.internet_facing ? '#7C2D12' : '#1E293B', border: '1px solid #334155', borderRadius: '4px' }}>
                  <Globe size={16} color={selectedNode.internet_facing ? '#FCD34D' : '#6B5AED'} />
                  <span style={{ fontSize: '12px' }}>{selectedNode.internet_facing ? 'Internet-Facing' : 'Internal'}</span>
                </div>
              </div>
            )}

            {selectedNode.has_pii !== undefined && selectedNode.has_pii && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>Data Classification</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#7C2D12', borderRadius: '4px' }}>
                  <Database size={16} color="#FCD34D" />
                  <span style={{ fontSize: '12px' }}>Contains PII</span>
                </div>
              </div>
            )}

            {selectedNode.criticality && (
              <div>
                <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '4px' }}>Business Criticality</div>
                <div style={{ fontSize: '14px', textTransform: 'capitalize' }}>{selectedNode.criticality.replace('_', ' ')}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default RiskGraph
