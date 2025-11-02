/**
 * Triage Adapter - Transforms pipeline output into flat triage rows
 * Supports Aikido-style list-first interface with filtering and sorting
 */

/**
 * Calculate FixOps risk score based on multiple factors
 * @param {Object} item - Triage item with severity, exploitability, exposure, etc.
 * @returns {number} Score from 0-100
 */
export function calculateFixOpsScore(item) {
  let score = 0
  
  const severityWeights = {
    critical: 40,
    high: 30,
    medium: 20,
    low: 10,
  }
  score += severityWeights[item.severity?.toLowerCase()] || 0
  
  if (item.exploited?.kev) {
    score += 15 // KEV = known exploited
  }
  if (item.exploited?.epss >= 0.7) {
    score += 10 // High EPSS score
  } else if (item.exploited?.epss >= 0.3) {
    score += 5 // Medium EPSS score
  }
  
  if (item.exposure === 'internet') {
    score += 15
  } else if (item.exposure === 'partner') {
    score += 8
  }
  
  if (item.business_impact === 'mission_critical') {
    score += 10
  } else if (item.business_impact === 'external') {
    score += 5
  }
  
  if (item.pii) {
    score += 5
  }
  
  if (item.shared_module) {
    score += 5
  }
  
  return Math.min(100, Math.round(score))
}

/**
 * Transform pipeline crosswalk data into triage rows
 * @param {Object} pipelineData - Full pipeline output
 * @returns {Array} Triage rows
 */
export function transformPipelineToTriage(pipelineData) {
  if (!pipelineData || !pipelineData.crosswalk) {
    return []
  }
  
  const rows = []
  const { crosswalk, context_summary, cnapp_summary } = pipelineData
  
  crosswalk.forEach((entry, index) => {
    const designRow = entry.design_row || {}
    const component = designRow.component || 'Unknown'
    const owner = designRow.owner || 'Unassigned'
    
    const componentContext = context_summary?.components?.find(
      c => c.name === component
    ) || {}
    
    const exposureInfo = cnapp_summary?.exposures?.find(
      e => e.service === component
    ) || {}
    
    const isInternetExposed = exposureInfo.traits?.includes('internet_exposed') || 
                              designRow.exposure === 'internet'
    const hasPII = designRow.data_classification?.includes('pii') || 
                   componentContext.data_classification?.includes('pii')
    
    if (entry.cves && entry.cves.length > 0) {
      entry.cves.forEach((cve, cveIndex) => {
        const severity = cve.severity?.toLowerCase() || 'low'
        const exploited = cve.exploited || false
        const epss = cve.epss_score || 0
        
        const item = {
          id: `cve-${index}-${cveIndex}`,
          service: component,
          component: component,
          type: 'CVE',
          name: cve.cve_id || cve.cveID || 'Unknown CVE',
          description: cve.title || cve.shortDescription || '',
          severity: severity,
          exploited: {
            kev: exploited,
            epss: epss,
          },
          exposure: isInternetExposed ? 'internet' : (designRow.exposure || 'internal'),
          pii: hasPII,
          business_impact: designRow.customer_impact || componentContext.criticality || 'internal',
          shared_module: false, // TODO: detect if component appears in multiple services
          sources: ['CVE'],
          owner: owner,
          age_days: 0, // TODO: calculate from CVE published date
          file: null,
          line: null,
          raw: cve,
        }
        
        item.fixops_score = calculateFixOpsScore(item)
        rows.push(item)
      })
    }
    
    if (entry.findings && entry.findings.length > 0) {
      entry.findings.forEach((finding, findingIndex) => {
        const level = finding.level?.toLowerCase() || 'info'
        const severityMap = {
          error: 'high',
          warning: 'medium',
          note: 'low',
          info: 'low',
        }
        const severity = severityMap[level] || 'low'
        
        const item = {
          id: `finding-${index}-${findingIndex}`,
          service: component,
          component: component,
          type: 'SAST',
          name: finding.rule_id || 'Unknown Rule',
          description: finding.message || '',
          severity: severity,
          exploited: {
            kev: false,
            epss: 0,
          },
          exposure: isInternetExposed ? 'internet' : (designRow.exposure || 'internal'),
          pii: hasPII,
          business_impact: designRow.customer_impact || componentContext.criticality || 'internal',
          shared_module: false,
          sources: ['SARIF'],
          owner: owner,
          age_days: 0,
          file: finding.file || null,
          line: finding.line || null,
          raw: finding,
        }
        
        item.fixops_score = calculateFixOpsScore(item)
        rows.push(item)
      })
    }
  })
  
  rows.sort((a, b) => b.fixops_score - a.fixops_score)
  
  return rows
}

/**
 * Filter triage rows based on criteria
 * @param {Array} rows - Triage rows
 * @param {Object} filters - Filter criteria
 * @returns {Array} Filtered rows
 */
export function filterTriageRows(rows, filters = {}) {
  return rows.filter(row => {
    if (filters.severity && filters.severity.length > 0) {
      if (!filters.severity.includes(row.severity)) {
        return false
      }
    }
    
    if (filters.exploitable) {
      if (!row.exploited.kev && row.exploited.epss < 0.7) {
        return false
      }
    }
    
    if (filters.internet_exposed) {
      if (row.exposure !== 'internet') {
        return false
      }
    }
    
    if (filters.pii) {
      if (!row.pii) {
        return false
      }
    }
    
    if (filters.mission_critical) {
      if (row.business_impact !== 'mission_critical') {
        return false
      }
    }
    
    if (filters.used_in_code) {
      if (!row.sources.includes('SARIF')) {
        return false
      }
    }
    
    if (filters.shared_module) {
      if (!row.shared_module) {
        return false
      }
    }
    
    if (filters.type && filters.type.length > 0) {
      if (!filters.type.includes(row.type)) {
        return false
      }
    }
    
    return true
  })
}

/**
 * Get filter counts for triage rows
 * @param {Array} rows - All triage rows
 * @returns {Object} Filter counts
 */
export function getFilterCounts(rows) {
  return {
    total: rows.length,
    exploitable: rows.filter(r => r.exploited.kev || r.exploited.epss >= 0.7).length,
    internet_exposed: rows.filter(r => r.exposure === 'internet').length,
    pii: rows.filter(r => r.pii).length,
    mission_critical: rows.filter(r => r.business_impact === 'mission_critical').length,
    used_in_code: rows.filter(r => r.sources.includes('SARIF')).length,
    shared_module: rows.filter(r => r.shared_module).length,
    by_severity: {
      critical: rows.filter(r => r.severity === 'critical').length,
      high: rows.filter(r => r.severity === 'high').length,
      medium: rows.filter(r => r.severity === 'medium').length,
      low: rows.filter(r => r.severity === 'low').length,
    },
    by_type: {
      CVE: rows.filter(r => r.type === 'CVE').length,
      SAST: rows.filter(r => r.type === 'SAST').length,
      CNAPP: rows.filter(r => r.type === 'CNAPP').length,
    },
  }
}

export default {
  transformPipelineToTriage,
  filterTriageRows,
  getFilterCounts,
  calculateFixOpsScore,
}
