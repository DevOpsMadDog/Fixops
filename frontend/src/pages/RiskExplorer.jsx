import React, { useState, useEffect } from 'react'
import RiskGraphExplorer from '../components/RiskGraphExplorer'
import ComponentDrawer from '../components/ComponentDrawer'
import AttackPathExplorer from '../components/AttackPathExplorer'
import aldeciTheme from '../theme/aldeci'
import { transformPipelineToGraph } from '../utils/graphAdapter'

const RiskExplorer = () => {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] })
  const [loading, setLoading] = useState(true)
  const [selectedItem, setSelectedItem] = useState(null)
  const [showAttackPath, setShowAttackPath] = useState(false)
  const [graphOptions, setGraphOptions] = useState({
    cluster_by: 'service',
    min_severity: null,
    kev_only: false,
    epss_min: 0,
    show_findings: false,
  })

  useEffect(() => {
    loadGraphData()
  }, [graphOptions])

  const loadGraphData = async () => {
    try {
      const params = new URLSearchParams()
      if (graphOptions.cluster_by) params.append('cluster_by', graphOptions.cluster_by)
      if (graphOptions.min_severity) params.append('min_severity', graphOptions.min_severity)
      if (graphOptions.kev_only) params.append('kev_only', 'true')
      if (graphOptions.epss_min > 0) params.append('epss_min', graphOptions.epss_min)
      if (graphOptions.show_findings) params.append('show_findings', 'true')

      const response = await fetch(`/api/v1/ui/graph?${params.toString()}`)
      if (response.ok) {
        const data = await response.json()
        setGraphData(data)
      } else {
        const demoResponse = await fetch('/tmp/pipeline-demo.json')
        if (demoResponse.ok) {
          const pipelineData = await demoResponse.json()
          const graph = transformPipelineToGraph(pipelineData, graphOptions)
          setGraphData(graph)
        }
      }
    } catch (error) {
      console.error('Failed to load graph data:', error)
      setGraphData({ nodes: [], edges: [] })
    } finally {
      setLoading(false)
    }
  }

  const handleNodeClick = (node) => {
    setSelectedItem(node)
    setShowAttackPath(node.type === 'cve')
  }

  const handleCloseDrawer = () => {
    setSelectedItem(null)
    setShowAttackPath(false)
  }

  const handleFilterChange = (key, value) => {
    setGraphOptions(prev => ({
      ...prev,
      [key]: value,
    }))
  }

  if (loading) {
    return (
      <div style={{
        height: '100vh',
        background: aldeciTheme.colors.bgPrimary,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        color: aldeciTheme.colors.textPrimary,
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '60px',
            height: '60px',
            border: `4px solid ${aldeciTheme.colors.borderPrimary}`,
            borderTop: `4px solid ${aldeciTheme.colors.primary}`,
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem auto',
          }}></div>
          <h2 style={{ fontSize: aldeciTheme.typography.fontSize.lg, fontWeight: aldeciTheme.typography.fontWeight.semibold }}>
            Loading Risk Graph...
          </h2>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      background: aldeciTheme.colors.bgPrimary,
      minHeight: '100vh',
      color: aldeciTheme.colors.textPrimary,
      fontFamily: aldeciTheme.typography.fontFamily,
      position: 'relative',
    }}>
      {/* Header */}
      <div style={{
        padding: aldeciTheme.spacing.md,
        borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
        backgroundColor: 'rgba(0, 0, 0, 0.3)',
      }}>
        <div style={{ maxWidth: '1800px', margin: '0 auto' }}>
          <h1 style={{
            fontSize: aldeciTheme.typography.fontSize.xxl,
            fontWeight: aldeciTheme.typography.fontWeight.bold,
            margin: 0,
          }}>
            Risk Graph Explorer
          </h1>
          <p style={{
            fontSize: aldeciTheme.typography.fontSize.base,
            color: aldeciTheme.colors.textSecondary,
            margin: `${aldeciTheme.spacing.xs} 0 0 0`,
          }}>
            Interactive visualization of services, components, and security findings
          </p>
        </div>
      </div>

      {/* Filter Controls */}
      <div style={{
        padding: aldeciTheme.spacing.md,
        borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
        backgroundColor: 'rgba(0, 0, 0, 0.2)',
      }}>
        <div style={{
          maxWidth: '1800px',
          margin: '0 auto',
          display: 'flex',
          gap: aldeciTheme.spacing.md,
          flexWrap: 'wrap',
          alignItems: 'center',
        }}>
          {/* KEV Only Toggle */}
          <label style={{
            display: 'flex',
            alignItems: 'center',
            gap: aldeciTheme.spacing.xs,
            cursor: 'pointer',
          }}>
            <input
              type="checkbox"
              checked={graphOptions.kev_only}
              onChange={(e) => handleFilterChange('kev_only', e.target.checked)}
              style={{
                width: '18px',
                height: '18px',
                cursor: 'pointer',
              }}
            />
            <span style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
            }}>
              🔥 KEV Only
            </span>
          </label>

          {/* Show Findings Toggle */}
          <label style={{
            display: 'flex',
            alignItems: 'center',
            gap: aldeciTheme.spacing.xs,
            cursor: 'pointer',
          }}>
            <input
              type="checkbox"
              checked={graphOptions.show_findings}
              onChange={(e) => handleFilterChange('show_findings', e.target.checked)}
              style={{
                width: '18px',
                height: '18px',
                cursor: 'pointer',
              }}
            />
            <span style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
            }}>
              💻 Show SARIF Findings
            </span>
          </label>

          {/* Min Severity Filter */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: aldeciTheme.spacing.xs,
          }}>
            <label style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
            }}>
              Min Severity:
            </label>
            <select
              value={graphOptions.min_severity || ''}
              onChange={(e) => handleFilterChange('min_severity', e.target.value || null)}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
                cursor: 'pointer',
              }}
            >
              <option value="">All</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          {/* EPSS Threshold */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: aldeciTheme.spacing.xs,
          }}>
            <label style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
            }}>
              EPSS ≥
            </label>
            <input
              type="number"
              min="0"
              max="1"
              step="0.1"
              value={graphOptions.epss_min}
              onChange={(e) => handleFilterChange('epss_min', parseFloat(e.target.value) || 0)}
              style={{
                width: '80px',
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
              }}
            />
          </div>
        </div>
      </div>

      {/* Graph Visualization */}
      <div style={{
        padding: aldeciTheme.spacing.md,
      }}>
        <div style={{ maxWidth: '1800px', margin: '0 auto' }}>
          <RiskGraphExplorer
            graphData={graphData}
            onNodeClick={handleNodeClick}
          />
        </div>
      </div>

      {/* Component Drawer */}
      {selectedItem && !showAttackPath && (
        <ComponentDrawer
          item={selectedItem}
          onClose={handleCloseDrawer}
        />
      )}

      {/* Attack Path Drawer */}
      {selectedItem && showAttackPath && (
        <div style={{
          position: 'fixed',
          top: 0,
          right: 0,
          width: '700px',
          height: '100vh',
          background: aldeciTheme.colors.bgCard,
          borderLeft: `1px solid ${aldeciTheme.colors.borderPrimary}`,
          boxShadow: aldeciTheme.shadows.lg,
          zIndex: 1000,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{
            padding: aldeciTheme.spacing.md,
            borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
          }}>
            <div style={{
              display: 'flex',
              gap: aldeciTheme.spacing.sm,
            }}>
              <button
                onClick={() => setShowAttackPath(false)}
                style={{
                  padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                  borderRadius: aldeciTheme.borderRadius.sm,
                  color: aldeciTheme.colors.textPrimary,
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  cursor: 'pointer',
                }}
              >
                ← Details
              </button>
              <button
                style={{
                  padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                  backgroundColor: aldeciTheme.colors.primary,
                  border: 'none',
                  borderRadius: aldeciTheme.borderRadius.sm,
                  color: aldeciTheme.colors.textPrimary,
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                }}
              >
                Attack Paths
              </button>
            </div>
            <button
              onClick={handleCloseDrawer}
              style={{
                background: 'transparent',
                border: 'none',
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.xl,
                cursor: 'pointer',
                padding: aldeciTheme.spacing.xs,
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </div>

          {/* Content */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            padding: aldeciTheme.spacing.md,
          }}>
            <AttackPathExplorer
              cveId={selectedItem.label || selectedItem.name}
              threatModelData={selectedItem.data?.raw}
            />
          </div>
        </div>
      )}
    </div>
  )
}

export default RiskExplorer
