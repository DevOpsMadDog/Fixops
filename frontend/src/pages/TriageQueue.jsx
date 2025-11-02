import React, { useState, useEffect } from 'react'
import aldeciTheme from '../theme/aldeci'
import { transformPipelineToTriage, filterTriageRows, getFilterCounts } from '../utils/triageAdapter'

const TriageQueue = ({ onItemClick }) => {
  const [triageData, setTriageData] = useState([])
  const [filteredData, setFilteredData] = useState([])
  const [filters, setFilters] = useState({
    severity: [],
    exploitable: false,
    internet_exposed: false,
    pii: false,
    mission_critical: false,
    used_in_code: false,
    shared_module: false,
    type: [],
  })
  const [filterCounts, setFilterCounts] = useState({})
  const [loading, setLoading] = useState(true)
  const [sortBy, setSortBy] = useState('fixops_score')
  const [sortOrder, setSortOrder] = useState('desc')

  useEffect(() => {
    loadTriageData()
  }, [])

  useEffect(() => {
    const filtered = filterTriageRows(triageData, filters)
    
    const sorted = [...filtered].sort((a, b) => {
      let aVal = a[sortBy]
      let bVal = b[sortBy]
      
      if (sortBy === 'exploited') {
        aVal = a.exploited.kev ? 1 : (a.exploited.epss >= 0.7 ? 0.5 : 0)
        bVal = b.exploited.kev ? 1 : (b.exploited.epss >= 0.7 ? 0.5 : 0)
      }
      
      if (sortOrder === 'asc') {
        return aVal > bVal ? 1 : -1
      } else {
        return aVal < bVal ? 1 : -1
      }
    })
    
    setFilteredData(sorted)
  }, [triageData, filters, sortBy, sortOrder])

  const loadTriageData = async () => {
    try {
      const response = await fetch('/api/v1/ui/triage')
      if (response.ok) {
        const data = await response.json()
        setTriageData(data.rows || [])
        setFilterCounts(getFilterCounts(data.rows || []))
      } else {
        const demoResponse = await fetch('/tmp/pipeline-demo.json')
        if (demoResponse.ok) {
          const pipelineData = await demoResponse.json()
          const rows = transformPipelineToTriage(pipelineData)
          setTriageData(rows)
          setFilterCounts(getFilterCounts(rows))
        }
      }
    } catch (error) {
      console.error('Failed to load triage data:', error)
      setTriageData([])
      setFilterCounts({})
    } finally {
      setLoading(false)
    }
  }

  const toggleFilter = (filterKey, value = null) => {
    setFilters(prev => {
      if (value !== null) {
        const currentValues = prev[filterKey] || []
        const newValues = currentValues.includes(value)
          ? currentValues.filter(v => v !== value)
          : [...currentValues, value]
        return { ...prev, [filterKey]: newValues }
      } else {
        return { ...prev, [filterKey]: !prev[filterKey] }
      }
    })
  }

  const getSeverityColor = (severity) => {
    return aldeciTheme.colors[severity] || aldeciTheme.colors.low
  }

  const getScoreColor = (score) => {
    if (score >= 80) return aldeciTheme.colors.critical
    if (score >= 60) return aldeciTheme.colors.high
    if (score >= 40) return aldeciTheme.colors.medium
    return aldeciTheme.colors.low
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
            Loading Triage Queue...
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
      padding: aldeciTheme.spacing.md,
    }}>
      <div style={{ maxWidth: '1800px', margin: '0 auto' }}>
        
        {/* Header */}
        <div style={{
          marginBottom: aldeciTheme.spacing.lg,
        }}>
          <h1 style={{
            fontSize: aldeciTheme.typography.fontSize.xxl,
            fontWeight: aldeciTheme.typography.fontWeight.bold,
            margin: 0,
            fontFamily: aldeciTheme.typography.fontFamily,
          }}>
            Security Triage Queue
          </h1>
          <p style={{
            fontSize: aldeciTheme.typography.fontSize.base,
            color: aldeciTheme.colors.textSecondary,
            margin: `${aldeciTheme.spacing.xs} 0 0 0`,
            fontFamily: aldeciTheme.typography.fontFamily,
          }}>
            {filteredData.length} of {triageData.length} issues • Sorted by {sortBy.replace('_', ' ')}
          </p>
        </div>

        {/* Filter Chips */}
        <div style={{
          background: aldeciTheme.colors.bgCard,
          borderRadius: aldeciTheme.borderRadius.lg,
          border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
          padding: aldeciTheme.spacing.md,
          marginBottom: aldeciTheme.spacing.md,
          boxShadow: aldeciTheme.shadows.md,
        }}>
          <h3 style={{
            fontSize: aldeciTheme.typography.fontSize.base,
            fontWeight: aldeciTheme.typography.fontWeight.semibold,
            margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            color: aldeciTheme.colors.primary,
            fontFamily: aldeciTheme.typography.fontFamily,
          }}>
            Filters
          </h3>

          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: aldeciTheme.spacing.sm,
          }}>
            {/* Severity filters */}
            {['critical', 'high', 'medium', 'low'].map(severity => (
              <button
                key={severity}
                onClick={() => toggleFilter('severity', severity)}
                style={{
                  padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                  backgroundColor: filters.severity.includes(severity)
                    ? getSeverityColor(severity)
                    : 'rgba(255, 255, 255, 0.1)',
                  border: `1px solid ${getSeverityColor(severity)}`,
                  borderRadius: aldeciTheme.borderRadius.sm,
                  color: aldeciTheme.colors.textPrimary,
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  fontWeight: aldeciTheme.typography.fontWeight.medium,
                  fontFamily: aldeciTheme.typography.fontFamily,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                  transition: 'all 0.2s ease',
                }}
              >
                {severity} ({filterCounts.by_severity?.[severity] || 0})
              </button>
            ))}

            {/* Context filters */}
            <button
              onClick={() => toggleFilter('exploitable')}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: filters.exploitable
                  ? aldeciTheme.colors.danger
                  : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.danger}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
                fontWeight: aldeciTheme.typography.fontWeight.medium,
                fontFamily: aldeciTheme.typography.fontFamily,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              🔥 Exploitable ({filterCounts.exploitable || 0})
            </button>

            <button
              onClick={() => toggleFilter('internet_exposed')}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: filters.internet_exposed
                  ? aldeciTheme.colors.warning
                  : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.warning}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
                fontWeight: aldeciTheme.typography.fontWeight.medium,
                fontFamily: aldeciTheme.typography.fontFamily,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              🌐 Internet Exposed ({filterCounts.internet_exposed || 0})
            </button>

            <button
              onClick={() => toggleFilter('pii')}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: filters.pii
                  ? aldeciTheme.colors.info
                  : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.info}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
                fontWeight: aldeciTheme.typography.fontWeight.medium,
                fontFamily: aldeciTheme.typography.fontFamily,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              🔒 PII ({filterCounts.pii || 0})
            </button>

            <button
              onClick={() => toggleFilter('mission_critical')}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: filters.mission_critical
                  ? aldeciTheme.colors.primary
                  : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.primary}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
                fontWeight: aldeciTheme.typography.fontWeight.medium,
                fontFamily: aldeciTheme.typography.fontFamily,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              ⭐ Mission Critical ({filterCounts.mission_critical || 0})
            </button>

            <button
              onClick={() => toggleFilter('used_in_code')}
              style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                backgroundColor: filters.used_in_code
                  ? aldeciTheme.colors.success
                  : 'rgba(255, 255, 255, 0.1)',
                border: `1px solid ${aldeciTheme.colors.success}`,
                borderRadius: aldeciTheme.borderRadius.sm,
                color: aldeciTheme.colors.textPrimary,
                fontSize: aldeciTheme.typography.fontSize.sm,
                fontWeight: aldeciTheme.typography.fontWeight.medium,
                fontFamily: aldeciTheme.typography.fontFamily,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              💻 Used in Code ({filterCounts.used_in_code || 0})
            </button>
          </div>
        </div>

        {/* Triage Table */}
        <div style={{
          background: aldeciTheme.colors.bgCard,
          borderRadius: aldeciTheme.borderRadius.lg,
          border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
          boxShadow: aldeciTheme.shadows.md,
          overflow: 'hidden',
        }}>
          {/* Table Header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '80px 1fr 120px 150px 120px 150px 120px 100px',
            gap: aldeciTheme.spacing.sm,
            padding: aldeciTheme.spacing.md,
            borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
            fontSize: aldeciTheme.typography.fontSize.xs,
            fontWeight: aldeciTheme.typography.fontWeight.semibold,
            color: aldeciTheme.colors.textSecondary,
            fontFamily: aldeciTheme.typography.fontFamily,
            textTransform: 'uppercase',
          }}>
            <div style={{ cursor: 'pointer' }} onClick={() => {
              setSortBy('fixops_score')
              setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
            }}>
              Score {sortBy === 'fixops_score' && (sortOrder === 'asc' ? '↑' : '↓')}
            </div>
            <div>Issue</div>
            <div style={{ cursor: 'pointer' }} onClick={() => {
              setSortBy('severity')
              setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
            }}>
              Severity {sortBy === 'severity' && (sortOrder === 'asc' ? '↑' : '↓')}
            </div>
            <div style={{ cursor: 'pointer' }} onClick={() => {
              setSortBy('exploited')
              setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
            }}>
              Exploitable {sortBy === 'exploited' && (sortOrder === 'asc' ? '↑' : '↓')}
            </div>
            <div>Exposure</div>
            <div>Service</div>
            <div>Owner</div>
            <div>Actions</div>
          </div>

          {/* Table Body */}
          <div style={{
            maxHeight: '600px',
            overflowY: 'auto',
          }}>
            {filteredData.length === 0 ? (
              <div style={{
                padding: aldeciTheme.spacing.xl,
                textAlign: 'center',
                color: aldeciTheme.colors.textSecondary,
                fontSize: aldeciTheme.typography.fontSize.base,
                fontFamily: aldeciTheme.typography.fontFamily,
              }}>
                No issues match the selected filters
              </div>
            ) : (
              filteredData.map((item, index) => (
                <div
                  key={item.id}
                  onClick={() => onItemClick && onItemClick(item)}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '80px 1fr 120px 150px 120px 150px 120px 100px',
                    gap: aldeciTheme.spacing.sm,
                    padding: aldeciTheme.spacing.md,
                    borderBottom: index < filteredData.length - 1 ? `1px solid ${aldeciTheme.colors.borderPrimary}` : 'none',
                    cursor: 'pointer',
                    transition: 'background-color 0.2s ease',
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    fontFamily: aldeciTheme.typography.fontFamily,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(107, 90, 237, 0.1)'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent'
                  }}
                >
                  {/* Score */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}>
                    <div style={{
                      width: '50px',
                      height: '50px',
                      borderRadius: '50%',
                      backgroundColor: getScoreColor(item.fixops_score),
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: aldeciTheme.typography.fontSize.md,
                      fontWeight: aldeciTheme.typography.fontWeight.bold,
                      color: aldeciTheme.colors.textPrimary,
                    }}>
                      {item.fixops_score}
                    </div>
                  </div>

                  {/* Issue */}
                  <div>
                    <div style={{
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      color: aldeciTheme.colors.textPrimary,
                      marginBottom: aldeciTheme.spacing.xs,
                    }}>
                      {item.name}
                    </div>
                    <div style={{
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      color: aldeciTheme.colors.textSecondary,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>
                      {item.description || 'No description'}
                    </div>
                    <div style={{
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      color: aldeciTheme.colors.textMuted,
                      marginTop: aldeciTheme.spacing.xs,
                    }}>
                      {item.type} • {item.sources.join(', ')}
                    </div>
                  </div>

                  {/* Severity */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                  }}>
                    <span style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: getSeverityColor(item.severity),
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      textTransform: 'uppercase',
                    }}>
                      {item.severity}
                    </span>
                  </div>

                  {/* Exploitable */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    flexDirection: 'column',
                    gap: aldeciTheme.spacing.xs,
                  }}>
                    {item.exploited.kev && (
                      <span style={{
                        padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                        backgroundColor: aldeciTheme.colors.danger,
                        borderRadius: aldeciTheme.borderRadius.sm,
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      }}>
                        KEV
                      </span>
                    )}
                    {item.exploited.epss > 0 && (
                      <span style={{
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        color: item.exploited.epss >= 0.7 ? aldeciTheme.colors.danger : aldeciTheme.colors.textSecondary,
                      }}>
                        EPSS: {(item.exploited.epss * 100).toFixed(1)}%
                      </span>
                    )}
                  </div>

                  {/* Exposure */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    flexDirection: 'column',
                    gap: aldeciTheme.spacing.xs,
                  }}>
                    <span style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: item.exposure === 'internet' ? aldeciTheme.colors.warning : 'rgba(255, 255, 255, 0.1)',
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      textTransform: 'capitalize',
                    }}>
                      {item.exposure}
                    </span>
                    {item.pii && (
                      <span style={{
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        color: aldeciTheme.colors.info,
                      }}>
                        🔒 PII
                      </span>
                    )}
                  </div>

                  {/* Service */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                  }}>
                    <div>
                      <div style={{
                        fontWeight: aldeciTheme.typography.fontWeight.medium,
                        color: aldeciTheme.colors.textPrimary,
                      }}>
                        {item.service}
                      </div>
                      {item.business_impact && (
                        <div style={{
                          fontSize: aldeciTheme.typography.fontSize.xs,
                          color: aldeciTheme.colors.textSecondary,
                          textTransform: 'capitalize',
                        }}>
                          {item.business_impact.replace('_', ' ')}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Owner */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    color: aldeciTheme.colors.textSecondary,
                  }}>
                    {item.owner}
                  </div>

                  {/* Actions */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: aldeciTheme.spacing.xs,
                  }}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        console.log('Accept risk:', item.id)
                      }}
                      style={{
                        padding: aldeciTheme.spacing.xs,
                        backgroundColor: 'rgba(255, 255, 255, 0.1)',
                        border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                        borderRadius: aldeciTheme.borderRadius.sm,
                        color: aldeciTheme.colors.textPrimary,
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                      title="Accept Risk"
                    >
                      ✓
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        console.log('Create ticket:', item.id)
                      }}
                      style={{
                        padding: aldeciTheme.spacing.xs,
                        backgroundColor: 'rgba(255, 255, 255, 0.1)',
                        border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                        borderRadius: aldeciTheme.borderRadius.sm,
                        color: aldeciTheme.colors.textPrimary,
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                      title="Create Ticket"
                    >
                      🎫
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default TriageQueue
