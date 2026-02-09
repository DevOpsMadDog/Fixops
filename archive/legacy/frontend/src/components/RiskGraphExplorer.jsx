import React, { useState, useEffect, useRef } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import Cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'
import aldeciTheme from '../theme/aldeci'

Cytoscape.use(coseBilkent)

const RiskGraphExplorer = ({ graphData, onNodeClick, selectedNode }) => {
  const [cy, setCy] = useState(null)
  const [layout, setLayout] = useState('cose-bilkent')
  const [filterSeverity, setFilterSeverity] = useState([])
  const cyRef = useRef(null)

  const stylesheet = [
    {
      selector: 'node',
      style: {
        'background-color': 'data(color)',
        'border-width': 2,
        'border-color': 'data(borderColor)',
        'label': 'data(label)',
        'color': '#ffffff',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'font-weight': '600',
        'font-family': aldeciTheme.typography.fontFamily,
        'width': 'data(size)',
        'height': 'data(size)',
        'text-wrap': 'wrap',
        'text-max-width': '80px',
      }
    },
    {
      selector: 'node[type="service"]',
      style: {
        'shape': 'roundrectangle',
        'background-color': aldeciTheme.graph.node.service.backgroundColor,
        'border-color': aldeciTheme.graph.node.service.borderColor,
      }
    },
    {
      selector: 'node[type="component"]',
      style: {
        'shape': 'ellipse',
        'background-color': aldeciTheme.graph.node.component.backgroundColor,
        'border-color': aldeciTheme.graph.node.component.borderColor,
      }
    },
    {
      selector: 'node[type="cve"]',
      style: {
        'shape': 'diamond',
      }
    },
    {
      selector: 'node[type="finding"]',
      style: {
        'shape': 'triangle',
      }
    },
    {
      selector: 'node[severity="critical"]',
      style: {
        'background-color': aldeciTheme.colors.critical,
        'border-color': '#ef4444',
      }
    },
    {
      selector: 'node[severity="high"]',
      style: {
        'background-color': aldeciTheme.colors.high,
        'border-color': '#fb923c',
      }
    },
    {
      selector: 'node[severity="medium"]',
      style: {
        'background-color': aldeciTheme.colors.medium,
        'border-color': '#fbbf24',
      }
    },
    {
      selector: 'node[severity="low"]',
      style: {
        'background-color': aldeciTheme.colors.low,
        'border-color': '#60a5fa',
      }
    },
    {
      selector: 'node[exploited="true"]',
      style: {
        'border-width': 4,
        'border-style': 'double',
      }
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 4,
        'border-color': aldeciTheme.colors.primary,
        'background-color': 'data(color)',
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': aldeciTheme.graph.edge.default,
        'target-arrow-color': aldeciTheme.graph.edge.default,
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 0.6,
      }
    },
    {
      selector: 'edge[relationship="exploits"]',
      style: {
        'line-color': aldeciTheme.graph.edge.critical,
        'target-arrow-color': aldeciTheme.graph.edge.critical,
        'width': 3,
        'opacity': 0.8,
      }
    },
    {
      selector: 'edge:selected',
      style: {
        'line-color': aldeciTheme.graph.edge.highlighted,
        'target-arrow-color': aldeciTheme.graph.edge.highlighted,
        'width': 3,
        'opacity': 1,
      }
    },
  ]

  const layoutConfig = {
    name: layout,
    animate: true,
    animationDuration: 500,
    fit: true,
    padding: 50,
    nodeDimensionsIncludeLabels: true,
    idealEdgeLength: 100,
    nodeRepulsion: 4500,
    gravity: 0.25,
    numIter: 2500,
    tile: true,
    tilingPaddingVertical: 10,
    tilingPaddingHorizontal: 10,
  }

  const transformGraphData = (data) => {
    if (!data || !data.nodes || !data.edges) {
      return { nodes: [], edges: [] }
    }

    const nodes = data.nodes
      .filter(node => {
        if (filterSeverity.length === 0) return true
        return filterSeverity.includes(node.severity)
      })
      .map(node => ({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          severity: node.severity,
          exploited: node.exploited,
          color: node.color || getNodeColor(node),
          borderColor: node.borderColor || getNodeBorderColor(node),
          size: node.size || getNodeSize(node),
          ...node.data,
        }
      }))

    const nodeIds = new Set(nodes.map(n => n.data.id))
    const edges = data.edges
      .filter(edge => nodeIds.has(edge.source) && nodeIds.has(edge.target))
      .map(edge => ({
        data: {
          id: edge.id || `${edge.source}-${edge.target}`,
          source: edge.source,
          target: edge.target,
          relationship: edge.relationship,
          ...edge.data,
        }
      }))

    return { nodes, edges }
  }

  const getNodeColor = (node) => {
    if (node.type === 'service') {
      return aldeciTheme.graph.node.service.backgroundColor
    }
    if (node.type === 'component') {
      return aldeciTheme.graph.node.component.backgroundColor
    }
    if (node.type === 'cve') {
      const severity = node.severity || 'low'
      return aldeciTheme.graph.node.cve[severity]?.backgroundColor || aldeciTheme.colors.low
    }
    if (node.type === 'finding') {
      const level = node.level || 'info'
      return aldeciTheme.graph.node.finding[level]?.backgroundColor || aldeciTheme.colors.info
    }
    return aldeciTheme.colors.primary
  }

  const getNodeBorderColor = (node) => {
    if (node.type === 'service') {
      return aldeciTheme.graph.node.service.borderColor
    }
    if (node.type === 'component') {
      return aldeciTheme.graph.node.component.borderColor
    }
    if (node.type === 'cve') {
      const severity = node.severity || 'low'
      return aldeciTheme.graph.node.cve[severity]?.borderColor || '#60a5fa'
    }
    if (node.type === 'finding') {
      const level = node.level || 'info'
      return aldeciTheme.graph.node.finding[level]?.borderColor || '#60a5fa'
    }
    return aldeciTheme.colors.primary
  }

  const getNodeSize = (node) => {
    if (node.type === 'service') return 60
    if (node.type === 'component') return 50
    if (node.type === 'cve') {
      if (node.severity === 'critical') return 45
      if (node.severity === 'high') return 40
      return 35
    }
    if (node.type === 'finding') return 35
    return 40
  }

  useEffect(() => {
    if (cy) {
      cy.on('tap', 'node', (evt) => {
        const node = evt.target
        if (onNodeClick) {
          onNodeClick(node.data())
        }
      })

      cy.on('tap', (evt) => {
        if (evt.target === cy && onNodeClick) {
          onNodeClick(null)
        }
      })
    }
  }, [cy, onNodeClick])

  useEffect(() => {
    if (cy && selectedNode) {
      cy.nodes().unselect()
      const node = cy.getElementById(selectedNode.id)
      if (node) {
        node.select()
        cy.animate({
          center: { eles: node },
          zoom: 1.5,
        }, {
          duration: 500
        })
      }
    }
  }, [cy, selectedNode])

  useEffect(() => {
    if (cy) {
      const transformed = transformGraphData(graphData)
      cy.elements().remove()
      cy.add(transformed.nodes)
      cy.add(transformed.edges)
      cy.layout(layoutConfig).run()
    }
  }, [filterSeverity, graphData])

  const elements = transformGraphData(graphData)

  const toggleSeverityFilter = (severity) => {
    setFilterSeverity(prev => 
      prev.includes(severity) 
        ? prev.filter(s => s !== severity)
        : [...prev, severity]
    )
  }

  const resetView = () => {
    if (cy) {
      cy.fit(50)
      cy.zoom(1)
    }
  }

  const changeLayout = (newLayout) => {
    setLayout(newLayout)
    if (cy) {
      cy.layout({ ...layoutConfig, name: newLayout }).run()
    }
  }

  return (
    <div style={{
      background: aldeciTheme.colors.bgCard,
      borderRadius: aldeciTheme.borderRadius.lg,
      border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
      boxShadow: aldeciTheme.shadows.md,
      overflow: 'hidden',
    }}>
      {/* Controls */}
      <div style={{
        padding: aldeciTheme.spacing.md,
        borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: aldeciTheme.spacing.sm,
      }}>
        <div>
          <h3 style={{
            margin: 0,
            fontSize: aldeciTheme.typography.fontSize.md,
            fontWeight: aldeciTheme.typography.fontWeight.semibold,
            color: aldeciTheme.colors.textPrimary,
            fontFamily: aldeciTheme.typography.fontFamily,
          }}>
            Risk Graph Explorer
          </h3>
          <p style={{
            margin: `${aldeciTheme.spacing.xs} 0 0 0`,
            fontSize: aldeciTheme.typography.fontSize.sm,
            color: aldeciTheme.colors.textSecondary,
            fontFamily: aldeciTheme.typography.fontFamily,
          }}>
            {elements.nodes.length} nodes, {elements.edges.length} relationships
          </p>
        </div>

        {/* Severity Filters */}
        <div style={{
          display: 'flex',
          gap: aldeciTheme.spacing.sm,
          flexWrap: 'wrap',
        }}>
          {['critical', 'high', 'medium', 'low'].map(severity => (
            <button
              key={severity}
              onClick={() => toggleSeverityFilter(severity)}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: filterSeverity.includes(severity) 
                  ? aldeciTheme.colors[severity]
                  : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors[severity]}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.xs,
                fontWeight: aldeciTheme.typography.fontWeight.medium,
                fontFamily: aldeciTheme.typography.fontFamily,
                cursor: 'pointer',
                textTransform: 'uppercase',
                transition: 'all 0.2s ease',
              }}
            >
              {severity}
            </button>
          ))}
        </div>

        {/* Layout Controls */}
        <div style={{
          display: 'flex',
          gap: aldeciTheme.spacing.sm,
        }}>
          <select
            value={layout}
            onChange={(e) => changeLayout(e.target.value)}
            style={{
              padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
              borderRadius: aldeciTheme.borderRadius.sm,
              color: aldeciTheme.colors.textPrimary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontFamily: aldeciTheme.typography.fontFamily,
              cursor: 'pointer',
            }}
          >
            <option value="cose-bilkent">Force-Directed</option>
            <option value="circle">Circle</option>
            <option value="grid">Grid</option>
            <option value="breadthfirst">Hierarchical</option>
          </select>

          <button
            onClick={resetView}
            style={{
              padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.md}`,
              backgroundColor: aldeciTheme.colors.primary,
              border: 'none',
              borderRadius: aldeciTheme.borderRadius.sm,
              color: aldeciTheme.colors.textPrimary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
              fontFamily: aldeciTheme.typography.fontFamily,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
          >
            Reset View
          </button>
        </div>
      </div>

      {/* Graph Canvas */}
      <div style={{ height: '600px', backgroundColor: aldeciTheme.colors.secondary }}>
        <CytoscapeComponent
          elements={CytoscapeComponent.normalizeElements(elements)}
          style={{ width: '100%', height: '100%' }}
          stylesheet={stylesheet}
          layout={layoutConfig}
          cy={(cyInstance) => {
            setCy(cyInstance)
            cyRef.current = cyInstance
          }}
          wheelSensitivity={0.2}
        />
      </div>

      {/* Legend */}
      <div style={{
        padding: aldeciTheme.spacing.md,
        borderTop: `1px solid ${aldeciTheme.colors.borderPrimary}`,
        display: 'flex',
        gap: aldeciTheme.spacing.lg,
        flexWrap: 'wrap',
        fontSize: aldeciTheme.typography.fontSize.xs,
        color: aldeciTheme.colors.textSecondary,
        fontFamily: aldeciTheme.typography.fontFamily,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: aldeciTheme.spacing.xs }}>
          <div style={{
            width: '16px',
            height: '16px',
            backgroundColor: aldeciTheme.graph.node.service.backgroundColor,
            borderRadius: aldeciTheme.borderRadius.sm,
          }}></div>
          <span>Services</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: aldeciTheme.spacing.xs }}>
          <div style={{
            width: '16px',
            height: '16px',
            backgroundColor: aldeciTheme.graph.node.component.backgroundColor,
            borderRadius: '50%',
          }}></div>
          <span>Components</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: aldeciTheme.spacing.xs }}>
          <div style={{
            width: '16px',
            height: '16px',
            backgroundColor: aldeciTheme.colors.critical,
            transform: 'rotate(45deg)',
          }}></div>
          <span>CVEs</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: aldeciTheme.spacing.xs }}>
          <div style={{
            width: 0,
            height: 0,
            borderLeft: '8px solid transparent',
            borderRight: '8px solid transparent',
            borderBottom: `16px solid ${aldeciTheme.colors.warning}`,
          }}></div>
          <span>Findings</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: aldeciTheme.spacing.xs }}>
          <div style={{
            width: '16px',
            height: '16px',
            border: `3px double ${aldeciTheme.colors.critical}`,
            borderRadius: '50%',
          }}></div>
          <span>Exploited (KEV)</span>
        </div>
      </div>
    </div>
  )
}

export default RiskGraphExplorer
