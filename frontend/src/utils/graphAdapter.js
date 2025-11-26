/**
 * Graph Adapter - Transforms pipeline output into Cytoscape graph format
 * Supports Apiiro-style Risk Graph visualization
 */

import aldeciTheme from '../theme/aldeci'

/**
 * Transform pipeline data into Cytoscape nodes and edges
 * @param {Object} pipelineData - Full pipeline output
 * @param {Object} options - Graph options (cluster_by, min_severity, kev_only, epss_min)
 * @returns {Object} { nodes, edges }
 */
export function transformPipelineToGraph(pipelineData, options = {}) {
  if (!pipelineData || !pipelineData.crosswalk) {
    return { nodes: [], edges: [] }
  }
  
  const {
    cluster_by = 'service',
    min_severity = null,
    kev_only = false,
    epss_min = 0,
    show_findings = false,
  } = options
  
  const nodes = []
  const edges = []
  const nodeIds = new Set()
  
  const { crosswalk, context_summary, cnapp_summary } = pipelineData
  
  const services = new Map()
  const components = new Map()
  
  crosswalk.forEach((entry, index) => {
    const designRow = entry.design_row || {}
    const serviceName = designRow.component || `service-${index}`
    const componentName = entry.sbom_component?.name || serviceName
    
    const componentContext = context_summary?.components?.find(
      c => c.name === serviceName
    ) || {}
    
    const exposureInfo = cnapp_summary?.exposures?.find(
      e => e.service === serviceName
    ) || {}
    
    const isInternetExposed = exposureInfo.traits?.includes('internet_exposed') || 
                              designRow.exposure === 'internet'
    const hasPII = designRow.data_classification?.includes('pii') || 
                   componentContext.data_classification?.includes('pii')
    
    if (!services.has(serviceName)) {
      const serviceId = `service-${serviceName}`
      services.set(serviceName, {
        id: serviceId,
        label: serviceName,
        type: 'service',
        exposure: isInternetExposed ? 'internet' : (designRow.exposure || 'internal'),
        pii: hasPII,
        business_impact: designRow.customer_impact || componentContext.criticality || 'internal',
        owner: designRow.owner || 'Unassigned',
        cve_count: 0,
        finding_count: 0,
      })
    }
    
    if (componentName !== serviceName && !components.has(componentName)) {
      const componentId = `component-${componentName}`
      components.set(componentName, {
        id: componentId,
        label: componentName,
        type: 'component',
        service: serviceName,
        version: entry.sbom_component?.version || 'unknown',
        cve_count: 0,
        finding_count: 0,
      })
      
      edges.push({
        id: `${services.get(serviceName).id}-${componentId}`,
        source: services.get(serviceName).id,
        target: componentId,
        relationship: 'uses',
      })
    }
    
    if (entry.cves && entry.cves.length > 0) {
      entry.cves.forEach((cve, cveIndex) => {
        const severity = cve.severity?.toLowerCase() || 'low'
        const exploited = cve.exploited || false
        const epss = cve.epss_score || 0
        
        if (min_severity) {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 }
          if (severityOrder[severity] < severityOrder[min_severity]) {
            return
          }
        }
        
        if (kev_only && !exploited) {
          return
        }
        
        if (epss_min > 0 && epss < epss_min) {
          return
        }
        
        const cveId = `cve-${index}-${cveIndex}`
        const cveLabel = cve.cve_id || cve.cveID || 'Unknown CVE'
        
        nodes.push({
          id: cveId,
          label: cveLabel,
          type: 'cve',
          severity: severity,
          exploited: exploited,
          epss: epss,
          description: cve.title || cve.shortDescription || '',
          data: {
            cve_id: cveLabel,
            severity: severity,
            exploited: exploited,
            epss: epss,
            raw: cve,
          },
        })
        nodeIds.add(cveId)
        
        const sourceId = components.has(componentName) 
          ? components.get(componentName).id 
          : services.get(serviceName).id
        
        edges.push({
          id: `${sourceId}-${cveId}`,
          source: sourceId,
          target: cveId,
          relationship: exploited ? 'exploits' : 'affects',
        })
        
        if (components.has(componentName)) {
          components.get(componentName).cve_count++
        }
        services.get(serviceName).cve_count++
      })
    }
    
    if (show_findings && entry.findings && entry.findings.length > 0) {
      entry.findings.forEach((finding, findingIndex) => {
        const level = finding.level?.toLowerCase() || 'info'
        const severityMap = {
          error: 'high',
          warning: 'medium',
          note: 'low',
          info: 'low',
        }
        const severity = severityMap[level] || 'low'
        
        if (min_severity) {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 }
          if (severityOrder[severity] < severityOrder[min_severity]) {
            return
          }
        }
        
        const findingId = `finding-${index}-${findingIndex}`
        const findingLabel = finding.rule_id || 'Unknown Rule'
        
        nodes.push({
          id: findingId,
          label: findingLabel,
          type: 'finding',
          level: level,
          severity: severity,
          description: finding.message || '',
          file: finding.file || null,
          line: finding.line || null,
          data: {
            rule_id: findingLabel,
            level: level,
            severity: severity,
            raw: finding,
          },
        })
        nodeIds.add(findingId)
        
        const sourceId = components.has(componentName) 
          ? components.get(componentName).id 
          : services.get(serviceName).id
        
        edges.push({
          id: `${sourceId}-${findingId}`,
          source: sourceId,
          target: findingId,
          relationship: 'has_finding',
        })
        
        if (components.has(componentName)) {
          components.get(componentName).finding_count++
        }
        services.get(serviceName).finding_count++
      })
    }
  })
  
  services.forEach(service => {
    nodes.push({
      id: service.id,
      label: `${service.label}\n(${service.cve_count} CVEs)`,
      type: 'service',
      severity: service.cve_count > 0 ? 'high' : 'low',
      data: service,
    })
    nodeIds.add(service.id)
  })
  
  components.forEach(component => {
    nodes.push({
      id: component.id,
      label: `${component.label}\n(${component.cve_count} CVEs)`,
      type: 'component',
      severity: component.cve_count > 0 ? 'medium' : 'low',
      data: component,
    })
    nodeIds.add(component.id)
  })
  
  return { nodes, edges }
}

/**
 * Get graph statistics
 * @param {Object} graph - Graph with nodes and edges
 * @returns {Object} Statistics
 */
export function getGraphStats(graph) {
  const { nodes, edges } = graph
  
  const stats = {
    total_nodes: nodes.length,
    total_edges: edges.length,
    by_type: {
      service: nodes.filter(n => n.type === 'service').length,
      component: nodes.filter(n => n.type === 'component').length,
      cve: nodes.filter(n => n.type === 'cve').length,
      finding: nodes.filter(n => n.type === 'finding').length,
    },
    by_severity: {
      critical: nodes.filter(n => n.severity === 'critical').length,
      high: nodes.filter(n => n.severity === 'high').length,
      medium: nodes.filter(n => n.severity === 'medium').length,
      low: nodes.filter(n => n.severity === 'low').length,
    },
    exploited: nodes.filter(n => n.type === 'cve' && n.exploited).length,
  }
  
  return stats
}

/**
 * Find node by ID
 * @param {Object} graph - Graph with nodes and edges
 * @param {string} nodeId - Node ID
 * @returns {Object|null} Node or null
 */
export function findNode(graph, nodeId) {
  return graph.nodes.find(n => n.id === nodeId) || null
}

/**
 * Get connected nodes
 * @param {Object} graph - Graph with nodes and edges
 * @param {string} nodeId - Node ID
 * @returns {Array} Connected nodes
 */
export function getConnectedNodes(graph, nodeId) {
  const { nodes, edges } = graph
  const connectedIds = new Set()
  
  edges.forEach(edge => {
    if (edge.source === nodeId) {
      connectedIds.add(edge.target)
    }
    if (edge.target === nodeId) {
      connectedIds.add(edge.source)
    }
  })
  
  return nodes.filter(n => connectedIds.has(n.id))
}

export default {
  transformPipelineToGraph,
  getGraphStats,
  findNode,
  getConnectedNodes,
}
