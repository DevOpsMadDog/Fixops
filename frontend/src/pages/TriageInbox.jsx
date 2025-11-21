import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, Shield, Code, Cloud, CheckCircle, XCircle, Copy, Ticket, FileKey, Info, Download, ChevronDown, ChevronUp, Network } from 'lucide-react'

const TriageInbox = () => {
  const navigate = useNavigate()
  const [issues, setIssues] = useState([])
  const [filteredIssues, setFilteredIssues] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedIssue, setSelectedIssue] = useState(null)
  const [showCapabilities, setShowCapabilities] = useState(false)
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
      const apiBase = import.meta.env.VITE_FIXOPS_API_BASE
      const apiToken = import.meta.env.VITE_FIXOPS_API_TOKEN
      
      let url = '/demo/triage.json'
      let headers = {}
      
      if (apiBase) {
        url = `${apiBase}/api/v1/triage`
        if (apiToken) {
          headers['X-API-Key'] = apiToken
        }
      }
      
      const response = await fetch(url, { headers })
      const data = await response.json()
      setIssues(data.rows || [])
      setSummary(data.summary || {})
    } catch (error) {
      console.error('Failed to load issues:', error)
      try {
        const fallbackResponse = await fetch('/demo/triage.json')
        const fallbackData = await fallbackResponse.json()
        setIssues(fallbackData.rows || [])
        setSummary(fallbackData.summary || {})
      } catch (fallbackError) {
        console.error('Fallback also failed:', fallbackError)
        setIssues([])
      }
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

  const copyEvidenceSummary = (issue) => {
    if (!issue.evidence_bundle) return
    const summary = `Evidence Bundle: ${issue.evidence_bundle.id}\nSignature: ${issue.evidence_bundle.signature_algorithm}\nSHA256: ${issue.evidence_bundle.sha256}\nRetained until: ${new Date(issue.evidence_bundle.retained_until).toLocaleDateString()}`
    navigator.clipboard.writeText(summary)
    alert('Evidence summary copied to clipboard!')
  }

  const getVerdictColor = (verdict) => {
    const colors = {
      block: '#dc2626',
      review: '#f59e0b',
      allow: '#10b981',
    }
    return colors[verdict] || '#94a3b8'
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
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                marginBottom: '8px',
              }}>
                <h1 style={{
                  fontSize: '24px',
                  fontWeight: '600',
                  margin: 0,
                  letterSpacing: '-0.02em',
                }}>
                  Security Triage
                </h1>
                <button
                  onClick={() => setShowCapabilities(!showCapabilities)}
                  style={{
                    padding: '4px 12px',
                    background: 'rgba(107, 90, 237, 0.1)',
                    border: '1px solid rgba(107, 90, 237, 0.3)',
                    borderRadius: '4px',
                    color: '#6B5AED',
                    fontSize: '12px',
                    fontWeight: '500',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                  title="What powers this?"
                >
                  <Info size={14} />
                  FixOps Capabilities
                  {showCapabilities ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
            </div>
            <button
              onClick={() => navigate('/risk')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                background: '#1E293B',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#E2E8F0',
                fontSize: '14px',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => { e.target.style.background = '#334155' }}
              onMouseLeave={(e) => { e.target.style.background = '#1E293B' }}
            >
              <Network size={16} />
              Risk Graph
            </button>
          </div>
          <div>
              <p style={{
                fontSize: '14px',
                color: '#94a3b8',
                margin: '4px 0 0 0',
              }}>
                {filteredIssues.length} of {issues.length} issues • Powered by evidence-based decision engine
              </p>
              
              {/* Capabilities Panel */}
              {showCapabilities && (
                <div style={{
                  marginTop: '16px',
                  padding: '16px',
                  background: 'rgba(107, 90, 237, 0.05)',
                  border: '1px solid rgba(107, 90, 237, 0.2)',
                  borderRadius: '6px',
                }}>
                  <div style={{
                    fontSize: '13px',
                    fontWeight: '600',
                    color: '#cbd5e1',
                    marginBottom: '12px',
                  }}>
                    What powers FixOps?
                  </div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, 1fr)',
                    gap: '12px',
                    fontSize: '13px',
                    color: '#94a3b8',
                    lineHeight: 1.6,
                  }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                        <FileKey size={14} color="#6B5AED" />
                        <span style={{ fontWeight: '600', color: '#cbd5e1' }}>Signed Evidence</span>
                      </div>
                      <div style={{ fontSize: '12px' }}>RSA-SHA256 signatures with 90-day (demo) or 7-year (enterprise) retention for audit compliance</div>
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                        <Shield size={14} color="#6B5AED" />
                        <span style={{ fontWeight: '600', color: '#cbd5e1' }}>SSVC Policy Gates</span>
                      </div>
                      <div style={{ fontSize: '12px' }}>Stakeholder-Specific Vulnerability Categorization for allow/review/block decisions</div>
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                        <AlertCircle size={14} color="#6B5AED" />
                        <span style={{ fontWeight: '600', color: '#cbd5e1' }}>Exploit Intelligence</span>
                      </div>
                      <div style={{ fontSize: '12px' }}>CISA KEV catalog + EPSS probability scores for prioritization</div>
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                        <CheckCircle size={14} color="#6B5AED" />
                        <span style={{ fontWeight: '600', color: '#cbd5e1' }}>Compliance Mapping</span>
                      </div>
                      <div style={{ fontSize: '12px' }}>Automatic mapping to SOC2, ISO27001, PCI-DSS, GDPR, OWASP controls</div>
                    </div>
                  </div>
                </div>
              )}
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

              {/* SSVC Decision */}
              {selectedIssue.decision && (
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
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}>
                    <Shield size={14} />
                    SSVC Decision
                  </h3>
                  <div style={{
                    padding: '16px',
                    background: 'rgba(0, 0, 0, 0.2)',
                    border: `1px solid ${getVerdictColor(selectedIssue.decision.verdict)}`,
                    borderRadius: '6px',
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '12px',
                    }}>
                      <div>
                        <div style={{
                          fontSize: '12px',
                          color: '#94a3b8',
                          marginBottom: '4px',
                        }}>
                          Verdict
                        </div>
                        <div style={{
                          fontSize: '16px',
                          fontWeight: '600',
                          color: getVerdictColor(selectedIssue.decision.verdict),
                          textTransform: 'uppercase',
                        }}>
                          {selectedIssue.decision.verdict}
                        </div>
                      </div>
                      <div style={{
                        textAlign: 'right',
                      }}>
                        <div style={{
                          fontSize: '12px',
                          color: '#94a3b8',
                          marginBottom: '4px',
                        }}>
                          Confidence
                        </div>
                        <div style={{
                          fontSize: '16px',
                          fontWeight: '600',
                          color: '#cbd5e1',
                        }}>
                          {(selectedIssue.decision.confidence * 100).toFixed(0)}%
                        </div>
                      </div>
                      <div style={{
                        textAlign: 'right',
                      }}>
                        <div style={{
                          fontSize: '12px',
                          color: '#94a3b8',
                          marginBottom: '4px',
                        }}>
                          SSVC Outcome
                        </div>
                        <div style={{
                          fontSize: '14px',
                          fontWeight: '600',
                          color: '#cbd5e1',
                          textTransform: 'capitalize',
                        }}>
                          {selectedIssue.decision.ssvc_outcome}
                        </div>
                      </div>
                    </div>
                    <div style={{
                      fontSize: '13px',
                      color: '#cbd5e1',
                      lineHeight: 1.6,
                      marginBottom: '12px',
                    }}>
                      {selectedIssue.decision.rationale}
                    </div>
                    <div style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '6px',
                    }}>
                      {selectedIssue.decision.signals.map((signal, idx) => (
                        <span
                          key={idx}
                          style={{
                            padding: '4px 8px',
                            background: 'rgba(107, 90, 237, 0.1)',
                            border: '1px solid rgba(107, 90, 237, 0.3)',
                            borderRadius: '4px',
                            fontSize: '11px',
                            color: '#a78bfa',
                          }}
                        >
                          {signal}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Evidence Bundle */}
              {selectedIssue.evidence_bundle && (
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
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}>
                    <FileKey size={14} />
                    Evidence Bundle
                  </h3>
                  <div style={{
                    padding: '16px',
                    background: 'rgba(0, 0, 0, 0.2)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '6px',
                  }}>
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      gap: '12px',
                      marginBottom: '12px',
                    }}>
                      <div>
                        <div style={{
                          fontSize: '11px',
                          color: '#64748b',
                          marginBottom: '4px',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em',
                        }}>
                          Bundle ID
                        </div>
                        <div style={{
                          fontSize: '12px',
                          color: '#cbd5e1',
                          fontFamily: 'JetBrains Mono, monospace',
                        }}>
                          {selectedIssue.evidence_bundle.id}
                        </div>
                      </div>
                      <div>
                        <div style={{
                          fontSize: '11px',
                          color: '#64748b',
                          marginBottom: '4px',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em',
                        }}>
                          Signature
                        </div>
                        <div style={{
                          fontSize: '12px',
                          color: '#cbd5e1',
                          fontFamily: 'JetBrains Mono, monospace',
                        }}>
                          {selectedIssue.evidence_bundle.signature_algorithm}
                        </div>
                      </div>
                      <div>
                        <div style={{
                          fontSize: '11px',
                          color: '#64748b',
                          marginBottom: '4px',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em',
                        }}>
                          Retention
                        </div>
                        <div style={{
                          fontSize: '12px',
                          color: '#cbd5e1',
                        }}>
                          {selectedIssue.evidence_bundle.retention_days} days (Demo)
                        </div>
                      </div>
                      <div>
                        <div style={{
                          fontSize: '11px',
                          color: '#64748b',
                          marginBottom: '4px',
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em',
                        }}>
                          Retained Until
                        </div>
                        <div style={{
                          fontSize: '12px',
                          color: '#cbd5e1',
                        }}>
                          {new Date(selectedIssue.evidence_bundle.retained_until).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                    <div style={{
                      marginBottom: '12px',
                    }}>
                      <div style={{
                        fontSize: '11px',
                        color: '#64748b',
                        marginBottom: '4px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                      }}>
                        SHA256 Checksum
                      </div>
                      <div style={{
                        fontSize: '11px',
                        color: '#94a3b8',
                        fontFamily: 'JetBrains Mono, monospace',
                        wordBreak: 'break-all',
                        lineHeight: 1.6,
                      }}>
                        {selectedIssue.evidence_bundle.sha256}
                      </div>
                    </div>
                    <button
                      onClick={() => copyEvidenceSummary(selectedIssue)}
                      style={{
                        padding: '8px 12px',
                        background: 'rgba(107, 90, 237, 0.1)',
                        border: '1px solid rgba(107, 90, 237, 0.3)',
                        borderRadius: '4px',
                        color: '#6B5AED',
                        fontSize: '12px',
                        fontWeight: '500',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      <Copy size={12} />
                      Copy Evidence Summary
                    </button>
                  </div>
                </div>
              )}

              {/* Compliance Mappings */}
              {selectedIssue.compliance_mappings && selectedIssue.compliance_mappings.length > 0 && (
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
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}>
                    <CheckCircle size={14} />
                    Compliance Mappings
                  </h3>
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                  }}>
                    {selectedIssue.compliance_mappings.map((mapping, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '12px',
                          background: 'rgba(0, 0, 0, 0.2)',
                          border: '1px solid rgba(255, 255, 255, 0.05)',
                          borderRadius: '4px',
                        }}
                      >
                        <div style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          marginBottom: '4px',
                        }}>
                          <span style={{
                            fontSize: '12px',
                            fontWeight: '600',
                            color: '#6B5AED',
                          }}>
                            {mapping.framework}
                          </span>
                          <span style={{
                            fontSize: '11px',
                            fontFamily: 'JetBrains Mono, monospace',
                            color: '#94a3b8',
                          }}>
                            {mapping.control}
                          </span>
                        </div>
                        <div style={{
                          fontSize: '12px',
                          color: '#94a3b8',
                        }}>
                          {mapping.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
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
