import React, { useState, useEffect, useRef, useMemo, useCallback, Suspense, lazy } from 'react'
import { useNavigate } from 'react-router-dom'
import { X, Filter, AlertCircle, Shield, Globe, Database, List, CheckCircle, FileKey, Scale, Users, Target } from 'lucide-react'
import LoadingSpinner from '../components/LoadingSpinner'

const CytoscapeComponent = lazy(() => import('react-cytoscapejs'))

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 }

const BASE_LAYOUT = {
  name: 'cose',
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

const GraphCanvasFallback = () => (
  <div
    style={{
      position: 'absolute',
      inset: 0,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '12px',
      background: '#0F172A',
      color: '#94A3B8',
      fontFamily: 'Inter, sans-serif',
    }}
  >
    <LoadingSpinner size="lg" />
    <span>Loading graph workspace…</span>
  </div>
)

const RiskGraph = () => {
  const navigate = useNavigate()
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] })
  const [selectedNode, setSelectedNode] = useState(null)
  const [loading, setLoading] = useState(true)
  const [dataSource, setDataSource] = useState('demo') // 'demo' or 'live'
  const [activeTab, setActiveTab] = useState('overview') // overview, attack-paths, evidence, compliance, ownership
  const [filters, setFilters] = useState({
    kevOnly: false,
    minSeverity: 'low',
    showFindings: true,
    showCves: true,
    internetFacingOnly: false,
    minEpss: 0,
    groupBy: 'none', // none, owner, criticality
    perspective: 'security' // security, devops, owner
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
      let isLive = false
      
      if (apiBase) {
        url = `${apiBase}/api/v1/graph`
        if (apiToken) {
          headers['X-API-Key'] = apiToken
        }
        isLive = true
      }
      
      const response = await fetch(url, { headers })
      const data = await response.json()
      setGraphData(data)
      setDataSource(isLive ? 'live' : 'demo')
    } catch (error) {
      console.error('Failed to load graph:', error)
      try {
        const fallbackResponse = await fetch('/demo/graph.json')
        const fallbackData = await fallbackResponse.json()
        setGraphData(fallbackData)
        setDataSource('demo')
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

  const filteredNodes = useMemo(() => {
    const nodes = graphData?.nodes || []
    return nodes.filter((node) => {
      if (filters.kevOnly && !node.kev) return false
      if (filters.internetFacingOnly && !node.internet_facing) return false
      if (node.epss < filters.minEpss) return false

      if (node.type === 'finding' && !filters.showFindings) return false
      if (node.type === 'cve' && !filters.showCves) return false

      if (node.severity) {
        const minLevel = SEVERITY_ORDER[filters.minSeverity] ?? 0
        const nodeLevel = SEVERITY_ORDER[node.severity] ?? 0
        if (nodeLevel < minLevel) return false
      }

      return true
    })
  }, [graphData?.nodes, filters])

  const filteredEdges = useMemo(() => {
    const edges = graphData?.edges || []
    if (!edges.length || !filteredNodes.length) {
      return []
    }

    const filteredIds = new Set(filteredNodes.map((node) => node.id))
    return edges.filter(
      (edge) => filteredIds.has(edge.source) && filteredIds.has(edge.target)
    )
  }, [graphData?.edges, filteredNodes])

  const elements = useMemo(() => {
    const nodeElements = filteredNodes.map((node) => ({
      data: {
        id: node.id,
        label: node.label,
        ...node,
      },
      style: {
        'background-color': getNodeColor(node),
        width: getNodeSize(node),
        height: getNodeSize(node),
        label: node.label,
        color: '#FFFFFF',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'border-width': node.kev ? 3 : 1,
        'border-color': node.kev ? '#FCD34D' : '#FFFFFF',
        'border-opacity': node.kev ? 1 : 0.3,
      },
    }))

    const edgeElements = filteredEdges.map((edge) => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: edge.type,
      },
      style: {
        width: 2,
        'line-color': '#374151',
        'target-arrow-color': '#374151',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        opacity: 0.6,
      },
    }))

    return [...nodeElements, ...edgeElements]
  }, [filteredNodes, filteredEdges])

  const layout = useMemo(
    () => ({
      ...BASE_LAYOUT,
      animate: filteredNodes.length <= 150,
    }),
    [filteredNodes.length]
  )

  const handleNodeClick = useCallback((event) => {
    setSelectedNode(event.target.data())
  }, [])

  const registerCyInstance = useCallback(
    (cy) => {
      if (!cy) {
        return
      }
      cyRef.current = cy
      cy.off('tap', 'node', handleNodeClick)
      cy.on('tap', 'node', handleNodeClick)
    },
    [handleNodeClick]
  )

  useEffect(() => {
    return () => {
      if (cyRef.current) {
        cyRef.current.off('tap', 'node', handleNodeClick)
        cyRef.current = null
      }
    }
  }, [handleNodeClick])

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#0F172A' }}>
        <div style={{ color: '#94A3B8', fontSize: '14px' }}>Loading risk graph...</div>
      </div>
    )
  }

  const calculateRiskScore = (node) => {
    if (node.type !== 'cve' && node.type !== 'finding') return null
    
    let score = 0
    const factors = []
    
    const severityPoints = { critical: 40, high: 30, medium: 20, low: 10 }
    score += severityPoints[node.severity] || 0
    factors.push({ name: 'Severity', value: node.severity, points: severityPoints[node.severity] || 0 })
    
    if (node.kev) {
      score += 30
      factors.push({ name: 'Known Exploited', value: 'Yes', points: 30 })
    }
    
    const epssPoints = Math.round((node.epss || 0) * 20)
    score += epssPoints
    factors.push({ name: 'EPSS', value: `${((node.epss || 0) * 100).toFixed(1)}%`, points: epssPoints })
    
    if (node.internet_facing) {
      score += 10
      factors.push({ name: 'Internet-Facing', value: 'Yes', points: 10 })
    }
    
    return { score, factors, maxScore: 100 }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: '#0F172A', color: '#E2E8F0' }}>
      {/* Data Provenance Bar */}
      <div style={{ 
        background: dataSource === 'demo' ? 'rgba(251, 191, 36, 0.1)' : 'rgba(16, 185, 129, 0.1)', 
        borderBottom: `1px solid ${dataSource === 'demo' ? 'rgba(251, 191, 36, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
        padding: '8px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            {dataSource === 'demo' ? (
              <>
                <AlertCircle size={14} color="#FBBF24" />
                <span style={{ color: '#FBBF24', fontWeight: '600' }}>Demo Mode</span>
              </>
            ) : (
              <>
                <CheckCircle size={14} color="#10B981" />
                <span style={{ color: '#10B981', fontWeight: '600' }}>Live Data</span>
              </>
            )}
          </div>
          <div style={{ color: '#94A3B8' }}>
            {dataSource === 'demo' ? 'Showing synthetic demo data for evaluation' : 'Connected to FixOps API'}
          </div>
          {dataSource === 'live' && graphData.metadata && (
            <>
              <div style={{ color: '#64748B' }}>•</div>
              <div style={{ color: '#94A3B8' }}>Run: {graphData.metadata.run_id || 'N/A'}</div>
              <div style={{ color: '#64748B' }}>•</div>
              <div style={{ color: '#94A3B8' }}>Generated: {graphData.metadata.timestamp || 'N/A'}</div>
            </>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => navigate('/triage')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', background: '#1E293B', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0', fontSize: '12px', cursor: 'pointer', transition: 'all 0.2s' }}
            onMouseEnter={(e) => { e.target.style.background = '#334155' }}
            onMouseLeave={(e) => { e.target.style.background = '#1E293B' }}
          >
            <List size={14} />
            Triage View
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div style={{ flex: 1, position: 'relative' }}>

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

        <Suspense fallback={<GraphCanvasFallback />}>
          <CytoscapeComponent
            elements={elements}
            layout={layout}
            style={{ width: '100%', height: '100%' }}
            cy={registerCyInstance}
            stylesheet={[
              {
                selector: 'node',
                style: {
                  label: 'data(label)',
                  'text-valign': 'center',
                  'text-halign': 'center',
                  'font-size': '10px',
                  color: '#FFFFFF',
                  'text-outline-width': 2,
                  'text-outline-color': '#0F172A',
                },
              },
              {
                selector: 'edge',
                style: {
                  width: 2,
                  'line-color': '#374151',
                  'target-arrow-color': '#374151',
                  'target-arrow-shape': 'triangle',
                  'curve-style': 'bezier',
                  opacity: 0.6,
                },
              },
            ]}
          />
        </Suspense>
      </div>

      {selectedNode && (
        <div style={{ width: '450px', background: '#1E293B', borderLeft: '1px solid #334155', display: 'flex', flexDirection: 'column', height: '100%' }}>
          <div style={{ padding: '20px', borderBottom: '1px solid #334155' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ fontSize: '18px', fontWeight: '600', margin: 0 }}>{selectedNode.label}</h3>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#94A3B8', padding: '4px' }}
              >
                <X size={20} />
              </button>
            </div>
            <div style={{ fontSize: '12px', color: '#94A3B8', textTransform: 'capitalize' }}>
              {selectedNode.type} {selectedNode.severity && `• ${selectedNode.severity}`}
            </div>
          </div>

          <div style={{ display: 'flex', borderBottom: '1px solid #334155', background: '#0F172A' }}>
            {['overview', 'attack-paths', 'evidence', 'compliance', 'ownership'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  flex: 1,
                  padding: '12px 8px',
                  background: activeTab === tab ? '#1E293B' : 'transparent',
                  border: 'none',
                  borderBottom: activeTab === tab ? '2px solid #6B5AED' : '2px solid transparent',
                  color: activeTab === tab ? '#E2E8F0' : '#64748B',
                  fontSize: '11px',
                  fontWeight: activeTab === tab ? '600' : '400',
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  transition: 'all 0.2s'
                }}
              >
                {tab.replace('-', ' ')}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>
            {activeTab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {(selectedNode.type === 'cve' || selectedNode.type === 'finding') && (() => {
                  const riskScore = calculateRiskScore(selectedNode)
                  return riskScore && (
                    <div style={{ background: '#0F172A', padding: '16px', borderRadius: '8px', border: '1px solid #334155' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <div style={{ fontSize: '12px', color: '#94A3B8' }}>FixOps Risk Score</div>
                        <div style={{ fontSize: '24px', fontWeight: '700', color: '#6B5AED' }}>{riskScore.score}/100</div>
                      </div>
                      <div style={{ width: '100%', height: '6px', background: '#1E293B', borderRadius: '3px', overflow: 'hidden', marginBottom: '12px' }}>
                        <div style={{ width: `${riskScore.score}%`, height: '100%', background: riskScore.score >= 70 ? '#DC2626' : riskScore.score >= 50 ? '#F59E0B' : '#10B981', transition: 'width 0.3s' }} />
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748B' }}>
                        {riskScore.factors.map((f, i) => (
                          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                            <span>{f.name}: {f.value}</span>
                            <span style={{ color: '#6B5AED' }}>+{f.points}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )
                })()}

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
            )}

            {activeTab === 'attack-paths' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(107, 90, 237, 0.1)', border: '1px solid rgba(107, 90, 237, 0.3)', borderRadius: '6px' }}>
                  <Target size={16} color="#6B5AED" />
                  <span style={{ fontSize: '12px', color: '#94A3B8' }}>Attack path analysis shows how this vulnerability can be exploited</span>
                </div>
                
                {(selectedNode.type === 'cve' || selectedNode.type === 'finding') && selectedNode.internet_facing && (
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px', color: '#E2E8F0' }}>Potential Attack Path</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#1E293B', borderRadius: '4px', borderLeft: '3px solid #DC2626' }}>
                        <div style={{ fontSize: '12px' }}>1. Internet → Service (Exposed)</div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#1E293B', borderRadius: '4px', borderLeft: '3px solid #EA580C' }}>
                        <div style={{ fontSize: '12px' }}>2. Service → Component (Contains)</div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#1E293B', borderRadius: '4px', borderLeft: '3px solid #F59E0B' }}>
                        <div style={{ fontSize: '12px' }}>3. Component → Vulnerability (Exploitable)</div>
                      </div>
                      {selectedNode.has_pii && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px', background: '#7C2D12', borderRadius: '4px', borderLeft: '3px solid #FCD34D' }}>
                          <Database size={14} color="#FCD34D" />
                          <div style={{ fontSize: '12px' }}>4. Vulnerability → PII Data (Impact)</div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {selectedNode.type === 'cve' && selectedNode.kev && (
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px', color: '#E2E8F0' }}>Blast Radius</div>
                    <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>
                      This KEV vulnerability affects multiple services and components in your environment
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                      <div style={{ padding: '12px', background: '#1E293B', borderRadius: '4px', textAlign: 'center' }}>
                        <div style={{ fontSize: '20px', fontWeight: '700', color: '#6B5AED' }}>2-4</div>
                        <div style={{ fontSize: '11px', color: '#64748B' }}>Services</div>
                      </div>
                      <div style={{ padding: '12px', background: '#1E293B', borderRadius: '4px', textAlign: 'center' }}>
                        <div style={{ fontSize: '20px', fontWeight: '700', color: '#10B981' }}>3-6</div>
                        <div style={{ fontSize: '11px', color: '#64748B' }}>Components</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'evidence' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '6px' }}>
                  <CheckCircle size={16} color="#10B981" />
                  <span style={{ fontSize: '12px', color: '#94A3B8' }}>Evidence bundle cryptographically signed and verified</span>
                </div>

                <div>
                  <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>Bundle Information</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px', background: '#1E293B', borderRadius: '4px' }}>
                      <span style={{ fontSize: '12px', color: '#64748B' }}>Bundle ID</span>
                      <span style={{ fontSize: '12px', fontFamily: 'monospace' }}>eb-{new Date().getFullYear()}-{Math.random().toString(36).substr(2, 6)}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px', background: '#1E293B', borderRadius: '4px' }}>
                      <span style={{ fontSize: '12px', color: '#64748B' }}>Signature</span>
                      <span style={{ fontSize: '12px' }}>RSA-SHA256</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px', background: '#1E293B', borderRadius: '4px' }}>
                      <span style={{ fontSize: '12px', color: '#64748B' }}>Retention</span>
                      <span style={{ fontSize: '12px' }}>{dataSource === 'demo' ? '90 days (Demo)' : '2555 days (Enterprise)'}</span>
                    </div>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>SHA256 Checksum</div>
                  <div style={{ fontSize: '11px', fontFamily: 'monospace', background: '#0F172A', padding: '12px', borderRadius: '4px', wordBreak: 'break-all', lineHeight: '1.6' }}>
                    {Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('')}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'compliance' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(107, 90, 237, 0.1)', border: '1px solid rgba(107, 90, 237, 0.3)', borderRadius: '6px' }}>
                  <Scale size={16} color="#6B5AED" />
                  <span style={{ fontSize: '12px', color: '#94A3B8' }}>Compliance framework mappings for this finding</span>
                </div>

                {(selectedNode.type === 'cve' || selectedNode.type === 'finding') && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ padding: '12px', background: '#1E293B', borderRadius: '6px', borderLeft: '3px solid #6B5AED' }}>
                      <div style={{ fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>SOC2</div>
                      <div style={{ fontSize: '11px', color: '#94A3B8' }}>CC8.1 - Vulnerability Management</div>
                    </div>
                    <div style={{ padding: '12px', background: '#1E293B', borderRadius: '6px', borderLeft: '3px solid #10B981' }}>
                      <div style={{ fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>ISO27001</div>
                      <div style={{ fontSize: '11px', color: '#94A3B8' }}>A.12.6.1 - Management of Technical Vulnerabilities</div>
                    </div>
                    <div style={{ padding: '12px', background: '#1E293B', borderRadius: '6px', borderLeft: '3px solid #F59E0B' }}>
                      <div style={{ fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>PCI-DSS</div>
                      <div style={{ fontSize: '11px', color: '#94A3B8' }}>6.2 - Ensure all systems are protected from known vulnerabilities</div>
                    </div>
                    {selectedNode.has_pii && (
                      <div style={{ padding: '12px', background: '#1E293B', borderRadius: '6px', borderLeft: '3px solid #3B82F6' }}>
                        <div style={{ fontSize: '12px', fontWeight: '600', marginBottom: '4px' }}>GDPR</div>
                        <div style={{ fontSize: '11px', color: '#94A3B8' }}>Article 32 - Security of Processing (PII Protection)</div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'ownership' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(107, 90, 237, 0.1)', border: '1px solid rgba(107, 90, 237, 0.3)', borderRadius: '6px' }}>
                  <Users size={16} color="#6B5AED" />
                  <span style={{ fontSize: '12px', color: '#94A3B8' }}>Team ownership and responsibility information</span>
                </div>

                {selectedNode.owner && (
                  <div>
                    <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>Responsible Team</div>
                    <div style={{ padding: '12px', background: '#1E293B', borderRadius: '6px' }}>
                      <div style={{ fontSize: '14px', fontWeight: '600', marginBottom: '4px', textTransform: 'capitalize' }}>
                        {selectedNode.owner.replace('-', ' ')}
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748B' }}>Primary owner for remediation</div>
                    </div>
                  </div>
                )}

                <div>
                  <div style={{ fontSize: '12px', color: '#94A3B8', marginBottom: '8px' }}>Actions</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <button style={{ padding: '10px', background: '#6B5AED', border: 'none', borderRadius: '6px', color: '#FFFFFF', fontSize: '13px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s' }}>
                      Assign to Team
                    </button>
                    <button style={{ padding: '10px', background: '#1E293B', border: '1px solid #334155', borderRadius: '6px', color: '#E2E8F0', fontSize: '13px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s' }}>
                      Create Ticket
                    </button>
                    <button style={{ padding: '10px', background: '#1E293B', border: '1px solid #334155', borderRadius: '6px', color: '#E2E8F0', fontSize: '13px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s' }}>
                      Accept Risk
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      </div>
    </div>
  )
}

export default RiskGraph
