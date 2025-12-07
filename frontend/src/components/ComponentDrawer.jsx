import React, { useState } from 'react'
import aldeciTheme from '../theme/aldeci'

const ComponentDrawer = ({ item, onClose }) => {
  const [activeTab, setActiveTab] = useState('overview')

  if (!item) return null

  const getSeverityColor = (severity) => {
    return aldeciTheme.colors[severity] || aldeciTheme.colors.low
  }

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'compliance', label: 'Compliance' },
    { id: 'decision', label: 'Decision' },
    { id: 'remediation', label: 'Remediation' },
  ]

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      right: 0,
      width: '600px',
      height: '100vh',
      background: aldeciTheme.colors.bgCard,
      borderLeft: `1px solid ${aldeciTheme.colors.borderPrimary}`,
      boxShadow: aldeciTheme.shadows.lg,
      zIndex: 1000,
      display: 'flex',
      flexDirection: 'column',
      fontFamily: aldeciTheme.typography.fontFamily,
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
        <div>
          <h2 style={{
            fontSize: aldeciTheme.typography.fontSize.lg,
            fontWeight: aldeciTheme.typography.fontWeight.bold,
            margin: 0,
            color: aldeciTheme.colors.textPrimary,
          }}>
            {item.name || item.label}
          </h2>
          <div style={{
            fontSize: aldeciTheme.typography.fontSize.sm,
            color: aldeciTheme.colors.textSecondary,
            marginTop: aldeciTheme.spacing.xs,
          }}>
            {item.type} • {item.service || item.component}
          </div>
        </div>
        <button
          onClick={onClose}
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

      {/* Tabs */}
      <div style={{
        display: 'flex',
        borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
        backgroundColor: 'rgba(0, 0, 0, 0.2)',
      }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              flex: 1,
              padding: aldeciTheme.spacing.sm,
              background: activeTab === tab.id ? aldeciTheme.colors.primary : 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? `2px solid ${aldeciTheme.colors.primary}` : '2px solid transparent',
              color: activeTab === tab.id ? aldeciTheme.colors.textPrimary : aldeciTheme.colors.textSecondary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: aldeciTheme.spacing.md,
      }}>
        {activeTab === 'overview' && (
          <div>
            {/* Severity Badge */}
            <div style={{ marginBottom: aldeciTheme.spacing.md }}>
              <label style={{
                fontSize: aldeciTheme.typography.fontSize.xs,
                color: aldeciTheme.colors.textSecondary,
                textTransform: 'uppercase',
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                display: 'block',
                marginBottom: aldeciTheme.spacing.xs,
              }}>
                Severity
              </label>
              <span style={{
                padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.md}`,
                backgroundColor: getSeverityColor(item.severity),
                borderRadius: aldeciTheme.borderRadius.sm,
                fontSize: aldeciTheme.typography.fontSize.base,
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                textTransform: 'uppercase',
                display: 'inline-block',
              }}>
                {item.severity}
              </span>
            </div>

            {/* FixOps Score */}
            {item.fixops_score !== undefined && (
              <div style={{ marginBottom: aldeciTheme.spacing.md }}>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  FixOps Risk Score
                </label>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: aldeciTheme.spacing.sm,
                }}>
                  <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '50%',
                    backgroundColor: item.fixops_score >= 80 ? aldeciTheme.colors.critical :
                                     item.fixops_score >= 60 ? aldeciTheme.colors.high :
                                     item.fixops_score >= 40 ? aldeciTheme.colors.medium :
                                     aldeciTheme.colors.low,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: aldeciTheme.typography.fontSize.xl,
                    fontWeight: aldeciTheme.typography.fontWeight.bold,
                    color: aldeciTheme.colors.textPrimary,
                  }}>
                    {item.fixops_score}
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    color: aldeciTheme.colors.textSecondary,
                  }}>
                    Calculated from severity, exploitability, exposure, business impact, and data sensitivity
                  </div>
                </div>
              </div>
            )}

            {/* Exploitability */}
            {item.exploited && (
              <div style={{ marginBottom: aldeciTheme.spacing.md }}>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Exploitability
                </label>
                <div style={{
                  display: 'flex',
                  gap: aldeciTheme.spacing.sm,
                  flexWrap: 'wrap',
                }}>
                  {item.exploited.kev && (
                    <span style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: aldeciTheme.colors.danger,
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.sm,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                    }}>
                      🔥 KEV - Known Exploited
                    </span>
                  )}
                  {item.exploited.epss > 0 && (
                    <span style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: item.exploited.epss >= 0.7 ? aldeciTheme.colors.danger : 'rgba(255, 255, 255, 0.1)',
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.sm,
                    }}>
                      EPSS: {(item.exploited.epss * 100).toFixed(1)}%
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Business Context */}
            <div style={{ marginBottom: aldeciTheme.spacing.md }}>
              <label style={{
                fontSize: aldeciTheme.typography.fontSize.xs,
                color: aldeciTheme.colors.textSecondary,
                textTransform: 'uppercase',
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                display: 'block',
                marginBottom: aldeciTheme.spacing.xs,
              }}>
                Business Context
              </label>
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: aldeciTheme.spacing.sm,
              }}>
                <div style={{
                  padding: aldeciTheme.spacing.sm,
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: aldeciTheme.borderRadius.sm,
                }}>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                    marginBottom: aldeciTheme.spacing.xs,
                  }}>
                    Exposure
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    color: aldeciTheme.colors.textPrimary,
                    fontWeight: aldeciTheme.typography.fontWeight.medium,
                    textTransform: 'capitalize',
                  }}>
                    {item.exposure || 'Unknown'}
                  </div>
                </div>
                <div style={{
                  padding: aldeciTheme.spacing.sm,
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: aldeciTheme.borderRadius.sm,
                }}>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                    marginBottom: aldeciTheme.spacing.xs,
                  }}>
                    Business Impact
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    color: aldeciTheme.colors.textPrimary,
                    fontWeight: aldeciTheme.typography.fontWeight.medium,
                    textTransform: 'capitalize',
                  }}>
                    {item.business_impact?.replace('_', ' ') || 'Unknown'}
                  </div>
                </div>
                <div style={{
                  padding: aldeciTheme.spacing.sm,
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: aldeciTheme.borderRadius.sm,
                }}>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                    marginBottom: aldeciTheme.spacing.xs,
                  }}>
                    PII Data
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    color: item.pii ? aldeciTheme.colors.info : aldeciTheme.colors.textPrimary,
                    fontWeight: aldeciTheme.typography.fontWeight.medium,
                  }}>
                    {item.pii ? '🔒 Yes' : 'No'}
                  </div>
                </div>
                <div style={{
                  padding: aldeciTheme.spacing.sm,
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: aldeciTheme.borderRadius.sm,
                }}>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                    marginBottom: aldeciTheme.spacing.xs,
                  }}>
                    Owner
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    color: aldeciTheme.colors.textPrimary,
                    fontWeight: aldeciTheme.typography.fontWeight.medium,
                  }}>
                    {item.owner || 'Unassigned'}
                  </div>
                </div>
              </div>
            </div>

            {/* Description */}
            {item.description && (
              <div style={{ marginBottom: aldeciTheme.spacing.md }}>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Description
                </label>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  color: aldeciTheme.colors.textPrimary,
                  lineHeight: 1.6,
                }}>
                  {item.description}
                </div>
              </div>
            )}

            {/* Sources */}
            {item.sources && item.sources.length > 0 && (
              <div style={{ marginBottom: aldeciTheme.spacing.md }}>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Detection Sources
                </label>
                <div style={{
                  display: 'flex',
                  gap: aldeciTheme.spacing.xs,
                  flexWrap: 'wrap',
                }}>
                  {item.sources.map(source => (
                    <span key={source} style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: 'rgba(107, 90, 237, 0.2)',
                      border: `1px solid ${aldeciTheme.colors.primary}`,
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      fontWeight: aldeciTheme.typography.fontWeight.medium,
                    }}>
                      {source}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* File Location */}
            {item.file && (
              <div style={{ marginBottom: aldeciTheme.spacing.md }}>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Location
                </label>
                <div style={{
                  padding: aldeciTheme.spacing.sm,
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: aldeciTheme.borderRadius.sm,
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  color: aldeciTheme.colors.textPrimary,
                  fontFamily: 'monospace',
                }}>
                  {item.file}{item.line ? `:${item.line}` : ''}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'evidence' && (
          <div>
            <div style={{
              padding: aldeciTheme.spacing.md,
              backgroundColor: 'rgba(107, 90, 237, 0.1)',
              border: `1px solid ${aldeciTheme.colors.borderAccent}`,
              borderRadius: aldeciTheme.borderRadius.md,
              marginBottom: aldeciTheme.spacing.md,
            }}>
              <h3 style={{
                fontSize: aldeciTheme.typography.fontSize.base,
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
                color: aldeciTheme.colors.primary,
              }}>
                Evidence Bundle
              </h3>
              <p style={{
                fontSize: aldeciTheme.typography.fontSize.sm,
                color: aldeciTheme.colors.textSecondary,
                margin: 0,
                lineHeight: 1.6,
              }}>
                Evidence bundles are cryptographically signed and stored with 90-day (demo) or 7-year (enterprise) retention for compliance audits.
              </p>
            </div>

            <div style={{ marginBottom: aldeciTheme.spacing.md }}>
              <label style={{
                fontSize: aldeciTheme.typography.fontSize.xs,
                color: aldeciTheme.colors.textSecondary,
                textTransform: 'uppercase',
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                display: 'block',
                marginBottom: aldeciTheme.spacing.xs,
              }}>
                Bundle Information
              </label>
              <div style={{
                padding: aldeciTheme.spacing.sm,
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                borderRadius: aldeciTheme.borderRadius.sm,
                fontSize: aldeciTheme.typography.fontSize.sm,
                color: aldeciTheme.colors.textSecondary,
              }}>
                Evidence bundle available via API endpoint
              </div>
            </div>

            <button style={{
              width: '100%',
              padding: aldeciTheme.spacing.sm,
              backgroundColor: aldeciTheme.colors.primary,
              border: 'none',
              borderRadius: aldeciTheme.borderRadius.md,
              color: aldeciTheme.colors.textPrimary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}>
              Download Evidence Bundle
            </button>
          </div>
        )}

        {activeTab === 'compliance' && (
          <div>
            <div style={{
              padding: aldeciTheme.spacing.md,
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              border: `1px solid ${aldeciTheme.colors.info}`,
              borderRadius: aldeciTheme.borderRadius.md,
              marginBottom: aldeciTheme.spacing.md,
            }}>
              <h3 style={{
                fontSize: aldeciTheme.typography.fontSize.base,
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
                color: aldeciTheme.colors.info,
              }}>
                Compliance Mapping
              </h3>
              <p style={{
                fontSize: aldeciTheme.typography.fontSize.sm,
                color: aldeciTheme.colors.textSecondary,
                margin: 0,
                lineHeight: 1.6,
              }}>
                This issue maps to the following compliance frameworks and controls.
              </p>
            </div>

            {['SOC2', 'ISO27001', 'PCI-DSS'].map(framework => (
              <div key={framework} style={{
                marginBottom: aldeciTheme.spacing.md,
                padding: aldeciTheme.spacing.sm,
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                borderRadius: aldeciTheme.borderRadius.sm,
              }}>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  color: aldeciTheme.colors.textPrimary,
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  {framework}
                </div>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                }}>
                  Relevant controls available in full compliance report
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'decision' && (
          <div>
            <div style={{
              padding: aldeciTheme.spacing.md,
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              border: `1px solid ${aldeciTheme.colors.success}`,
              borderRadius: aldeciTheme.borderRadius.md,
              marginBottom: aldeciTheme.spacing.md,
            }}>
              <h3 style={{
                fontSize: aldeciTheme.typography.fontSize.base,
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
                color: aldeciTheme.colors.success,
              }}>
                Multi-LLM Decision Analysis
              </h3>
              <p style={{
                fontSize: aldeciTheme.typography.fontSize.sm,
                color: aldeciTheme.colors.textSecondary,
                margin: 0,
                lineHeight: 1.6,
              }}>
                FixOps uses multiple LLM models to analyze and provide consensus recommendations.
              </p>
            </div>

            <div style={{
              padding: aldeciTheme.spacing.md,
              backgroundColor: 'rgba(255, 255, 255, 0.05)',
              borderRadius: aldeciTheme.borderRadius.sm,
              marginBottom: aldeciTheme.spacing.md,
            }}>
              <div style={{
                fontSize: aldeciTheme.typography.fontSize.sm,
                color: aldeciTheme.colors.textSecondary,
                lineHeight: 1.6,
              }}>
                Decision analysis available when multi-LLM processing is enabled
              </div>
            </div>
          </div>
        )}

        {activeTab === 'remediation' && (
          <div>
            <div style={{
              padding: aldeciTheme.spacing.md,
              backgroundColor: 'rgba(245, 158, 11, 0.1)',
              border: `1px solid ${aldeciTheme.colors.warning}`,
              borderRadius: aldeciTheme.borderRadius.md,
              marginBottom: aldeciTheme.spacing.md,
            }}>
              <h3 style={{
                fontSize: aldeciTheme.typography.fontSize.base,
                fontWeight: aldeciTheme.typography.fontWeight.semibold,
                margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
                color: aldeciTheme.colors.warning,
              }}>
                Recommended Actions
              </h3>
              <p style={{
                fontSize: aldeciTheme.typography.fontSize.sm,
                color: aldeciTheme.colors.textSecondary,
                margin: 0,
                lineHeight: 1.6,
              }}>
                Follow these steps to remediate this security issue.
              </p>
            </div>

            <div style={{
              marginBottom: aldeciTheme.spacing.md,
            }}>
              {item.type === 'CVE' && (
                <ol style={{
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  color: aldeciTheme.colors.textPrimary,
                  lineHeight: 1.8,
                  paddingLeft: aldeciTheme.spacing.lg,
                }}>
                  <li>Update the affected component to the latest patched version</li>
                  <li>Review and test the update in a staging environment</li>
                  <li>Deploy the update to production</li>
                  <li>Verify the CVE is resolved in the next scan</li>
                </ol>
              )}
              {item.type === 'SAST' && (
                <ol style={{
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  color: aldeciTheme.colors.textPrimary,
                  lineHeight: 1.8,
                  paddingLeft: aldeciTheme.spacing.lg,
                }}>
                  <li>Review the code at {item.file}:{item.line}</li>
                  <li>Apply the recommended code fix</li>
                  <li>Run tests to ensure no regressions</li>
                  <li>Create a pull request with the fix</li>
                </ol>
              )}
            </div>

            <button style={{
              width: '100%',
              padding: aldeciTheme.spacing.sm,
              backgroundColor: aldeciTheme.colors.primary,
              border: 'none',
              borderRadius: aldeciTheme.borderRadius.md,
              color: aldeciTheme.colors.textPrimary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              marginBottom: aldeciTheme.spacing.sm,
            }}>
              Create Jira Ticket
            </button>

            <button style={{
              width: '100%',
              padding: aldeciTheme.spacing.sm,
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
              borderRadius: aldeciTheme.borderRadius.md,
              color: aldeciTheme.colors.textPrimary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}>
              Accept Risk
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default ComponentDrawer
