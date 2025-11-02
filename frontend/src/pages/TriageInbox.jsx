import React, { useState, useEffect } from 'react'
import { AlertCircle, Shield, Code, Cloud, CheckCircle, XCircle, Copy, Ticket } from 'lucide-react'

const TriageInbox = () => {
  const [issues, setIssues] = useState([])
  const [filteredIssues, setFilteredIssues] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedIssue, setSelectedIssue] = useState(null)
  const [filters, setFilters] = useState({
    new_7d: false,
    high_critical: false,
    exploitable: false,
    internet_facing: false,
  })
  const [summary, setSummary] = useState({
    total: 0,
    new_7d: 0,
    high_critical: 0,
    exploitable: 0,
    internet_facing: 0,
  })

  useEffect(() => {
    loadIssues()
  }, [])

  useEffect(() => {
    applyFilters()
  }, [filters, issues])

  const loadIssues = async () => {
    try {
      const response = await fetch('/demo/triage.json')
      const data = await response.json()
      setIssues(data.rows || [])
      setSummary(data.summary || {})
    } catch (error) {
      console.error('Failed to load issues:', error)
      setIssues([])
    } finally {
      setLoading(false)
    }
  }

  const applyFilters = () => {
    let filtered = [...issues]

    if (filters.new_7d) {
      filtered = filtered.filter(issue => issue.age_days <= 7)
    }

    if (filters.high_critical) {
      filtered = filtered.filter(issue => 
        issue.severity === 'high' || issue.severity === 'critical'
      )
    }

    if (filters.exploitable) {
      filtered = filtered.filter(issue => 
        issue.exploitability.kev || issue.exploitability.epss >= 0.7
      )
    }

    if (filters.internet_facing) {
      filtered = filtered.filter(issue => issue.internet_facing)
    }

    setFilteredIssues(filtered)
  }

  const toggleFilter = (filterKey) => {
    setFilters(prev => ({
      ...prev,
      [filterKey]: !prev[filterKey],
    }))
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#f97316',
      medium: '#f59e0b',
      low: '#3b82f6',
    }
    return colors[severity] || colors.low
  }

  const getSourceIcon = (source) => {
    const icons = {
      CVE: Shield,
      SAST: Code,
      IaC: Cloud,
    }
    return icons[source] || AlertCircle
  }

  const copyFixGuidance = (issue) => {
    const guidance = `Issue: ${issue.title}\nLocation: ${issue.location}\nRemediation: ${issue.remediation}`
    navigator.clipboard.writeText(guidance)
    alert('Fix guidance copied to clipboard!')
  }

  const createTicket = (issue) => {
    alert(`Creating ticket for: ${issue.title}\n(Jira integration not configured)`)
  }

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        background: '#0f172a',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}>
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '16px',
        }}>
          <div style={{
            width: '48px',
            height: '48px',
            border: '3px solid rgba(107, 90, 237, 0.3)',
            borderTopColor: '#6B5AED',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
          }}></div>
          <div style={{
            color: '#94a3b8',
            fontSize: '14px',
            fontFamily: 'Inter, sans-serif',
          }}>
            Loading security issues...
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0f172a',
      fontFamily: 'Inter, sans-serif',
      color: '#ffffff',
    }}>
      {/* Header */}
      <div style={{
        borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
        background: 'rgba(15, 23, 42, 0.8)',
        backdropFilter: 'blur(8px)',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}>
        <div style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '24px 32px',
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '24px',
          }}>
            <div>
              <h1 style={{
                fontSize: '24px',
                fontWeight: '600',
                margin: 0,
                letterSpacing: '-0.02em',
              }}>
                Security Triage
              </h1>
              <p style={{
                fontSize: '14px',
                color: '#94a3b8',
                margin: '4px 0 0 0',
              }}>
                {filteredIssues.length} of {issues.length} issues
              </p>
            </div>

            {/* Summary Stats */}
            <div style={{
              display: 'flex',
              gap: '24px',
            }}>
              <div style={{
                textAlign: 'center',
              }}>
                <div style={{
                  fontSize: '24px',
                  fontWeight: '600',
                  color: '#6B5AED',
                }}>
                  {summary.new_7d}
                </div>
                <div style={{
                  fontSize: '12px',
                  color: '#64748b',
                  marginTop: '4px',
                }}>
                  New (7d)
                </div>
              </div>
              <div style={{
                textAlign: 'center',
              }}>
                <div style={{
                  fontSize: '24px',
                  fontWeight: '600',
                  color: '#f97316',
                }}>
                  {summary.high_critical}
                </div>
                <div style={{
                  fontSize: '12px',
                  color: '#64748b',
                  marginTop: '4px',
                }}>
                  High/Critical
                </div>
              </div>
              <div style={{
                textAlign: 'center',
              }}>
                <div style={{
                  fontSize: '24px',
                  fontWeight: '600',
                  color: '#dc2626',
                }}>
                  {summary.exploitable}
                </div>
                <div style={{
                  fontSize: '12px',
                  color: '#64748b',
                  marginTop: '4px',
                }}>
                  Exploitable
                </div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div style={{
            display: 'flex',
            gap: '12px',
            flexWrap: 'wrap',
          }}>
            <button
              onClick={() => toggleFilter('new_7d')}
              style={{
                padding: '8px 16px',
                background: filters.new_7d ? '#6B5AED' : 'rgba(255, 255, 255, 0.05)',
                border: `1px solid ${filters.new_7d ? '#6B5AED' : 'rgba(255, 255, 255, 0.1)'}`,
                borderRadius: '6px',
                color: '#ffffff',
                fontSize: '13px',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              New (7d)
              <span style={{
                background: filters.new_7d ? 'rgba(255, 255, 255, 0.2)' : 'rgba(107, 90, 237, 0.2)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
              }}>
                {summary.new_7d}
              </span>
            </button>

            <button
              onClick={() => toggleFilter('high_critical')}
              style={{
                padding: '8px 16px',
                background: filters.high_critical ? '#f97316' : 'rgba(255, 255, 255, 0.05)',
                border: `1px solid ${filters.high_critical ? '#f97316' : 'rgba(255, 255, 255, 0.1)'}`,
                borderRadius: '6px',
                color: '#ffffff',
                fontSize: '13px',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              High/Critical
              <span style={{
                background: filters.high_critical ? 'rgba(255, 255, 255, 0.2)' : 'rgba(249, 115, 22, 0.2)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
              }}>
                {summary.high_critical}
              </span>
            </button>

            <button
              onClick={() => toggleFilter('exploitable')}
              style={{
                padding: '8px 16px',
                background: filters.exploitable ? '#dc2626' : 'rgba(255, 255, 255, 0.05)',
                border: `1px solid ${filters.exploitable ? '#dc2626' : 'rgba(255, 255, 255, 0.1)'}`,
                borderRadius: '6px',
                color: '#ffffff',
                fontSize: '13px',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              Exploitable
              <span style={{
                background: filters.exploitable ? 'rgba(255, 255, 255, 0.2)' : 'rgba(220, 38, 38, 0.2)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
              }}>
                {summary.exploitable}
              </span>
            </button>

            <button
              onClick={() => toggleFilter('internet_facing')}
              style={{
                padding: '8px 16px',
                background: filters.internet_facing ? '#6B5AED' : 'rgba(255, 255, 255, 0.05)',
                border: `1px solid ${filters.internet_facing ? '#6B5AED' : 'rgba(255, 255, 255, 0.1)'}`,
                borderRadius: '6px',
                color: '#ffffff',
                fontSize: '13px',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              Internet-facing
              <span style={{
                background: filters.internet_facing ? 'rgba(255, 255, 255, 0.2)' : 'rgba(107, 90, 237, 0.2)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '600',
              }}>
                {summary.internet_facing}
              </span>
            </button>

            {(filters.new_7d || filters.high_critical || filters.exploitable || filters.internet_facing) && (
              <button
                onClick={() => setFilters({
                  new_7d: false,
                  high_critical: false,
                  exploitable: false,
                  internet_facing: false,
                })}
                style={{
                  padding: '8px 16px',
                  background: 'transparent',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '6px',
                  color: '#94a3b8',
                  fontSize: '13px',
                  fontWeight: '500',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                Reset filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Issues Table */}
      <div style={{
        maxWidth: '1600px',
        margin: '0 auto',
        padding: '32px',
      }}>
        {filteredIssues.length === 0 ? (
          <div style={{
            textAlign: 'center',
            padding: '64px 32px',
            background: 'rgba(255, 255, 255, 0.02)',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.05)',
          }}>
            <div style={{
              fontSize: '48px',
              marginBottom: '16px',
            }}>
              <CheckCircle size={48} color="#10b981" />
            </div>
            <h3 style={{
              fontSize: '18px',
              fontWeight: '600',
              margin: '0 0 8px 0',
            }}>
              No issues found
            </h3>
            <p style={{
              fontSize: '14px',
              color: '#94a3b8',
              margin: 0,
            }}>
              {Object.values(filters).some(v => v) 
                ? 'Try adjusting your filters to see more results'
                : 'All security issues have been resolved'}
            </p>
          </div>
        ) : (
          <div style={{
            background: 'rgba(255, 255, 255, 0.02)',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            overflow: 'hidden',
          }}>
            {/* Table Header */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '80px 1fr 100px 200px 200px 140px 80px',
              gap: '16px',
              padding: '16px 24px',
              background: 'rgba(0, 0, 0, 0.2)',
              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
              fontSize: '12px',
              fontWeight: '600',
              color: '#94a3b8',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>
              <div>Severity</div>
              <div>Issue</div>
              <div>Source</div>
              <div>Repository</div>
              <div>Location</div>
              <div>Exploitability</div>
              <div>Age</div>
            </div>

            {/* Table Body */}
            {filteredIssues.map((issue, index) => {
              const SourceIcon = getSourceIcon(issue.source)
              return (
                <div
                  key={issue.id}
                  onClick={() => setSelectedIssue(issue)}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '80px 1fr 100px 200px 200px 140px 80px',
                    gap: '16px',
                    padding: '20px 24px',
                    borderBottom: index < filteredIssues.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                    cursor: 'pointer',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = 'rgba(107, 90, 237, 0.05)'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent'
                  }}
                >
                  {/* Severity */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                  }}>
                    <div style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      background: getSeverityColor(issue.severity),
                      marginRight: '8px',
                    }}></div>
                    <span style={{
                      fontSize: '13px',
                      fontWeight: '500',
                      color: getSeverityColor(issue.severity),
                      textTransform: 'capitalize',
                    }}>
                      {issue.severity}
                    </span>
                  </div>

                  {/* Issue */}
                  <div>
                    <div style={{
                      fontSize: '14px',
                      fontWeight: '500',
                      color: '#ffffff',
                      marginBottom: '4px',
                    }}>
                      {issue.title}
                    </div>
                  </div>

                  {/* Source */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}>
                    <SourceIcon size={14} color="#94a3b8" />
                    <span style={{
                      fontSize: '13px',
                      color: '#94a3b8',
                    }}>
                      {issue.source}
                    </span>
                  </div>

                  {/* Repository */}
                  <div style={{
                    fontSize: '13px',
                    color: '#94a3b8',
                    fontFamily: 'JetBrains Mono, monospace',
                  }}>
                    {issue.repo}
                  </div>

                  {/* Location */}
                  <div style={{
                    fontSize: '12px',
                    color: '#64748b',
                    fontFamily: 'JetBrains Mono, monospace',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}>
                    {issue.location}
                  </div>

                  {/* Exploitability */}
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}>
                    {issue.exploitability.kev && (
                      <span style={{
                        padding: '2px 8px',
                        background: 'rgba(220, 38, 38, 0.2)',
                        border: '1px solid rgba(220, 38, 38, 0.3)',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '600',
                        color: '#fca5a5',
                        textAlign: 'center',
                      }}>
                        KEV
                      </span>
                    )}
                    {issue.exploitability.epss > 0 && (
                      <span style={{
                        fontSize: '12px',
                        color: issue.exploitability.epss >= 0.7 ? '#fca5a5' : '#94a3b8',
                      }}>
                        EPSS: {(issue.exploitability.epss * 100).toFixed(0)}%
                      </span>
                    )}
                  </div>

                  {/* Age */}
                  <div style={{
                    fontSize: '13px',
                    color: issue.age_days <= 7 ? '#6B5AED' : '#94a3b8',
                  }}>
                    {issue.age_days}d
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Issue Drawer */}
      {selectedIssue && (
        <div
          onClick={() => setSelectedIssue(null)}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(4px)',
            zIndex: 50,
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '600px',
              height: '100vh',
              background: '#1e293b',
              borderLeft: '1px solid rgba(255, 255, 255, 0.1)',
              display: 'flex',
              flexDirection: 'column',
              animation: 'slideIn 0.2s ease',
            }}
          >
            {/* Drawer Header */}
            <div style={{
              padding: '24px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
              background: 'rgba(0, 0, 0, 0.2)',
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'start',
                marginBottom: '16px',
              }}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}>
                  <div style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: getSeverityColor(selectedIssue.severity),
                  }}></div>
                  <span style={{
                    fontSize: '12px',
                    fontWeight: '600',
                    color: getSeverityColor(selectedIssue.severity),
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                  }}>
                    {selectedIssue.severity}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedIssue(null)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#94a3b8',
                    fontSize: '24px',
                    cursor: 'pointer',
                    padding: '0',
                    lineHeight: 1,
                  }}
                >
                  ×
                </button>
              </div>
              <h2 style={{
                fontSize: '18px',
                fontWeight: '600',
                margin: '0 0 8px 0',
                lineHeight: 1.4,
              }}>
                {selectedIssue.title}
              </h2>
              <div style={{
                display: 'flex',
                gap: '12px',
                fontSize: '13px',
                color: '#94a3b8',
              }}>
                <span>{selectedIssue.source}</span>
                <span>•</span>
                <span>{selectedIssue.repo}</span>
                <span>•</span>
                <span>{selectedIssue.age_days}d old</span>
              </div>
            </div>

            {/* Drawer Content */}
            <div style={{
              flex: 1,
              overflowY: 'auto',
              padding: '24px',
            }}>
              {/* Overview */}
              <div style={{
                marginBottom: '32px',
              }}>
                <h3 style={{
                  fontSize: '14px',
                  fontWeight: '600',
                  color: '#94a3b8',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  margin: '0 0 16px 0',
                }}>
                  Overview
                </h3>
                <div style={{
                  fontSize: '14px',
                  color: '#cbd5e1',
                  lineHeight: 1.6,
                  marginBottom: '16px',
                }}>
                  {selectedIssue.description}
                </div>
                <div style={{
                  background: 'rgba(0, 0, 0, 0.2)',
                  borderRadius: '6px',
                  padding: '12px',
                  fontSize: '13px',
                  fontFamily: 'JetBrains Mono, monospace',
                  color: '#94a3b8',
                  wordBreak: 'break-all',
                }}>
                  {selectedIssue.location}
                </div>
              </div>

              {/* Exploitability */}
              {(selectedIssue.exploitability.kev || selectedIssue.exploitability.epss > 0) && (
                <div style={{
                  marginBottom: '32px',
                }}>
                  <h3 style={{
                    fontSize: '14px',
                    fontWeight: '600',
                    color: '#94a3b8',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    margin: '0 0 16px 0',
                  }}>
                    Exploitability
                  </h3>
                  <div style={{
                    display: 'flex',
                    gap: '12px',
                  }}>
                    {selectedIssue.exploitability.kev && (
                      <div style={{
                        flex: 1,
                        padding: '12px',
                        background: 'rgba(220, 38, 38, 0.1)',
                        border: '1px solid rgba(220, 38, 38, 0.2)',
                        borderRadius: '6px',
                      }}>
                        <div style={{
                          fontSize: '12px',
                          color: '#94a3b8',
                          marginBottom: '4px',
                        }}>
                          KEV Status
                        </div>
                        <div style={{
                          fontSize: '14px',
                          fontWeight: '600',
                          color: '#fca5a5',
                        }}>
                          Known Exploited
                        </div>
                      </div>
                    )}
                    {selectedIssue.exploitability.epss > 0 && (
                      <div style={{
                        flex: 1,
                        padding: '12px',
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        borderRadius: '6px',
                      }}>
                        <div style={{
                          fontSize: '12px',
                          color: '#94a3b8',
                          marginBottom: '4px',
                        }}>
                          EPSS Score
                        </div>
                        <div style={{
                          fontSize: '14px',
                          fontWeight: '600',
                          color: selectedIssue.exploitability.epss >= 0.7 ? '#fca5a5' : '#cbd5e1',
                        }}>
                          {(selectedIssue.exploitability.epss * 100).toFixed(1)}%
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Remediation */}
              <div style={{
                marginBottom: '32px',
              }}>
                <h3 style={{
                  fontSize: '14px',
                  fontWeight: '600',
                  color: '#94a3b8',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  margin: '0 0 16px 0',
                }}>
                  Remediation
                </h3>
                <div style={{
                  fontSize: '14px',
                  color: '#cbd5e1',
                  lineHeight: 1.6,
                  padding: '16px',
                  background: 'rgba(107, 90, 237, 0.05)',
                  border: '1px solid rgba(107, 90, 237, 0.2)',
                  borderRadius: '6px',
                }}>
                  {selectedIssue.remediation}
                </div>
              </div>
            </div>

            {/* Drawer Actions */}
            <div style={{
              padding: '24px',
              borderTop: '1px solid rgba(255, 255, 255, 0.1)',
              background: 'rgba(0, 0, 0, 0.2)',
              display: 'flex',
              gap: '12px',
            }}>
              <button
                onClick={() => copyFixGuidance(selectedIssue)}
                style={{
                  flex: 1,
                  padding: '12px',
                  background: '#6B5AED',
                  border: 'none',
                  borderRadius: '6px',
                  color: '#ffffff',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  transition: 'background 0.15s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = '#5a4ad4'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = '#6B5AED'
                }}
              >
                <Copy size={16} />
                Copy Fix Guidance
              </button>
              <button
                onClick={() => createTicket(selectedIssue)}
                style={{
                  flex: 1,
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '6px',
                  color: '#ffffff',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)'
                }}
              >
                <Ticket size={16} />
                Create Ticket
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes slideIn {
          from {
            transform: translateX(100%);
          }
          to {
            transform: translateX(0);
          }
        }
      `}</style>
    </div>
  )
}

export default TriageInbox
