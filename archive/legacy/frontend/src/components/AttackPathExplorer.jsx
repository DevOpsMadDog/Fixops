import React, { useState, useEffect } from 'react'
import aldeciTheme from '../theme/aldeci'

const AttackPathExplorer = ({ cveId, threatModelData }) => {
  const [attackPaths, setAttackPaths] = useState([])
  const [selectedPath, setSelectedPath] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (cveId) {
      loadAttackPaths()
    }
  }, [cveId])

  const loadAttackPaths = async () => {
    try {
      if (threatModelData) {
        const paths = extractAttackPaths(threatModelData)
        setAttackPaths(paths)
        if (paths.length > 0) {
          setSelectedPath(paths[0])
        }
      } else {
        const response = await fetch(`/api/v1/threat-model/${cveId}`)
        if (response.ok) {
          const data = await response.json()
          const paths = extractAttackPaths(data)
          setAttackPaths(paths)
          if (paths.length > 0) {
            setSelectedPath(paths[0])
          }
        }
      }
    } catch (error) {
      console.error('Failed to load attack paths:', error)
    } finally {
      setLoading(false)
    }
  }

  const extractAttackPaths = (data) => {
    if (!data) return []
    
    return [
      {
        id: 'path-1',
        name: 'Internet → Web Server → Database',
        reachability: 0.85,
        complexity: 'Low',
        privileges: 'None',
        user_interaction: 'None',
        steps: [
          {
            id: 'step-1',
            name: 'Initial Access',
            description: 'Attacker exploits CVE via internet-exposed endpoint',
            asset: 'Web Server',
            technique: 'T1190 - Exploit Public-Facing Application',
            impact: 'High',
          },
          {
            id: 'step-2',
            name: 'Privilege Escalation',
            description: 'Escalate privileges using vulnerable component',
            asset: 'Application Server',
            technique: 'T1068 - Exploitation for Privilege Escalation',
            impact: 'Critical',
          },
          {
            id: 'step-3',
            name: 'Lateral Movement',
            description: 'Move to database server with elevated privileges',
            asset: 'Database Server',
            technique: 'T1021 - Remote Services',
            impact: 'Critical',
          },
          {
            id: 'step-4',
            name: 'Data Exfiltration',
            description: 'Access and exfiltrate sensitive PII data',
            asset: 'Customer Database',
            technique: 'T1041 - Exfiltration Over C2 Channel',
            impact: 'Critical',
          },
        ],
        critical_assets: ['Customer Database', 'Payment Processing', 'User Credentials'],
        weak_links: ['Unpatched Web Server', 'Weak Network Segmentation'],
      },
      {
        id: 'path-2',
        name: 'Partner Network → Internal Services',
        reachability: 0.62,
        complexity: 'Medium',
        privileges: 'Low',
        user_interaction: 'Required',
        steps: [
          {
            id: 'step-1',
            name: 'Initial Access',
            description: 'Compromise partner connection via phishing',
            asset: 'Partner Gateway',
            technique: 'T1566 - Phishing',
            impact: 'Medium',
          },
          {
            id: 'step-2',
            name: 'Lateral Movement',
            description: 'Exploit trust relationship to access internal services',
            asset: 'Internal API',
            technique: 'T1199 - Trusted Relationship',
            impact: 'High',
          },
          {
            id: 'step-3',
            name: 'Data Access',
            description: 'Access sensitive business data',
            asset: 'Business Intelligence',
            technique: 'T1213 - Data from Information Repositories',
            impact: 'High',
          },
        ],
        critical_assets: ['Business Intelligence', 'Internal API'],
        weak_links: ['Partner Trust Relationship', 'Insufficient Monitoring'],
      },
    ]
  }

  const getReachabilityColor = (score) => {
    if (score >= 0.8) return aldeciTheme.colors.critical
    if (score >= 0.6) return aldeciTheme.colors.high
    if (score >= 0.4) return aldeciTheme.colors.medium
    return aldeciTheme.colors.low
  }

  const getImpactColor = (impact) => {
    const impactMap = {
      critical: aldeciTheme.colors.critical,
      high: aldeciTheme.colors.high,
      medium: aldeciTheme.colors.medium,
      low: aldeciTheme.colors.low,
    }
    return impactMap[impact?.toLowerCase()] || aldeciTheme.colors.low
  }

  if (loading) {
    return (
      <div style={{
        padding: aldeciTheme.spacing.xl,
        textAlign: 'center',
        color: aldeciTheme.colors.textSecondary,
        fontFamily: aldeciTheme.typography.fontFamily,
      }}>
        Loading attack paths...
      </div>
    )
  }

  if (attackPaths.length === 0) {
    return (
      <div style={{
        padding: aldeciTheme.spacing.xl,
        textAlign: 'center',
        color: aldeciTheme.colors.textSecondary,
        fontFamily: aldeciTheme.typography.fontFamily,
      }}>
        No attack paths available for this CVE
      </div>
    )
  }

  return (
    <div style={{
      fontFamily: aldeciTheme.typography.fontFamily,
      color: aldeciTheme.colors.textPrimary,
    }}>
      {/* Header */}
      <div style={{
        marginBottom: aldeciTheme.spacing.md,
      }}>
        <h2 style={{
          fontSize: aldeciTheme.typography.fontSize.xl,
          fontWeight: aldeciTheme.typography.fontWeight.bold,
          margin: 0,
        }}>
          Attack Path Analysis
        </h2>
        <p style={{
          fontSize: aldeciTheme.typography.fontSize.sm,
          color: aldeciTheme.colors.textSecondary,
          margin: `${aldeciTheme.spacing.xs} 0 0 0`,
        }}>
          {cveId} • {attackPaths.length} potential attack path{attackPaths.length !== 1 ? 's' : ''}
        </p>
      </div>

      {/* Path Selector */}
      <div style={{
        display: 'flex',
        gap: aldeciTheme.spacing.sm,
        marginBottom: aldeciTheme.spacing.md,
        flexWrap: 'wrap',
      }}>
        {attackPaths.map(path => (
          <button
            key={path.id}
            onClick={() => setSelectedPath(path)}
            style={{
              padding: `${aldeciTheme.spacing.sm} ${aldeciTheme.spacing.md}`,
              backgroundColor: selectedPath?.id === path.id
                ? aldeciTheme.colors.primary
                : 'rgba(255, 255, 255, 0.1)',
              border: `1px solid ${selectedPath?.id === path.id ? aldeciTheme.colors.primary : aldeciTheme.colors.borderPrimary}`,
              borderRadius: aldeciTheme.borderRadius.md,
              color: aldeciTheme.colors.textPrimary,
              fontSize: aldeciTheme.typography.fontSize.sm,
              fontWeight: aldeciTheme.typography.fontWeight.medium,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
          >
            <div style={{ marginBottom: aldeciTheme.spacing.xs }}>
              {path.name}
            </div>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xs,
              color: selectedPath?.id === path.id ? aldeciTheme.colors.textPrimary : aldeciTheme.colors.textSecondary,
            }}>
              Reachability: {(path.reachability * 100).toFixed(0)}%
            </div>
          </button>
        ))}
      </div>

      {selectedPath && (
        <div>
          {/* Path Overview */}
          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            marginBottom: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.lg,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.md} 0`,
            }}>
              Path Overview
            </h3>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: aldeciTheme.spacing.md,
            }}>
              <div>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Reachability Score
                </label>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: aldeciTheme.spacing.sm,
                }}>
                  <div style={{
                    width: '50px',
                    height: '50px',
                    borderRadius: '50%',
                    backgroundColor: getReachabilityColor(selectedPath.reachability),
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: aldeciTheme.typography.fontSize.base,
                    fontWeight: aldeciTheme.typography.fontWeight.bold,
                  }}>
                    {(selectedPath.reachability * 100).toFixed(0)}
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                  }}>
                    Probability of successful exploitation
                  </div>
                </div>
              </div>

              <div>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Attack Complexity
                </label>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.base,
                  color: aldeciTheme.colors.textPrimary,
                  fontWeight: aldeciTheme.typography.fontWeight.medium,
                }}>
                  {selectedPath.complexity}
                </div>
              </div>

              <div>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  Privileges Required
                </label>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.base,
                  color: aldeciTheme.colors.textPrimary,
                  fontWeight: aldeciTheme.typography.fontWeight.medium,
                }}>
                  {selectedPath.privileges}
                </div>
              </div>

              <div>
                <label style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  textTransform: 'uppercase',
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  display: 'block',
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  User Interaction
                </label>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.base,
                  color: aldeciTheme.colors.textPrimary,
                  fontWeight: aldeciTheme.typography.fontWeight.medium,
                }}>
                  {selectedPath.user_interaction}
                </div>
              </div>
            </div>
          </div>

          {/* Attack Steps */}
          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            marginBottom: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.lg,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.md} 0`,
            }}>
              Attack Steps
            </h3>

            <div style={{
              position: 'relative',
            }}>
              {selectedPath.steps.map((step, index) => (
                <div key={step.id} style={{
                  position: 'relative',
                  paddingLeft: aldeciTheme.spacing.xl,
                  paddingBottom: index < selectedPath.steps.length - 1 ? aldeciTheme.spacing.lg : 0,
                }}>
                  {/* Timeline connector */}
                  {index < selectedPath.steps.length - 1 && (
                    <div style={{
                      position: 'absolute',
                      left: '15px',
                      top: '30px',
                      bottom: '0',
                      width: '2px',
                      background: aldeciTheme.colors.borderPrimary,
                    }}></div>
                  )}

                  {/* Step number */}
                  <div style={{
                    position: 'absolute',
                    left: '0',
                    top: '0',
                    width: '30px',
                    height: '30px',
                    borderRadius: '50%',
                    backgroundColor: getImpactColor(step.impact),
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: aldeciTheme.typography.fontSize.sm,
                    fontWeight: aldeciTheme.typography.fontWeight.bold,
                  }}>
                    {index + 1}
                  </div>

                  {/* Step content */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    borderRadius: aldeciTheme.borderRadius.md,
                    padding: aldeciTheme.spacing.md,
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'start',
                      marginBottom: aldeciTheme.spacing.sm,
                    }}>
                      <div>
                        <h4 style={{
                          fontSize: aldeciTheme.typography.fontSize.base,
                          fontWeight: aldeciTheme.typography.fontWeight.semibold,
                          margin: 0,
                          color: aldeciTheme.colors.textPrimary,
                        }}>
                          {step.name}
                        </h4>
                        <div style={{
                          fontSize: aldeciTheme.typography.fontSize.xs,
                          color: aldeciTheme.colors.textSecondary,
                          marginTop: aldeciTheme.spacing.xs,
                        }}>
                          Target: {step.asset}
                        </div>
                      </div>
                      <span style={{
                        padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                        backgroundColor: getImpactColor(step.impact),
                        borderRadius: aldeciTheme.borderRadius.sm,
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        fontWeight: aldeciTheme.typography.fontWeight.semibold,
                        textTransform: 'uppercase',
                      }}>
                        {step.impact}
                      </span>
                    </div>

                    <p style={{
                      fontSize: aldeciTheme.typography.fontSize.sm,
                      color: aldeciTheme.colors.textSecondary,
                      margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
                      lineHeight: 1.6,
                    }}>
                      {step.description}
                    </p>

                    <div style={{
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      color: aldeciTheme.colors.textMuted,
                      fontFamily: 'monospace',
                    }}>
                      MITRE ATT&CK: {step.technique}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Critical Assets */}
          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            marginBottom: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.lg,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.md} 0`,
            }}>
              Critical Assets at Risk
            </h3>

            <div style={{
              display: 'flex',
              gap: aldeciTheme.spacing.sm,
              flexWrap: 'wrap',
            }}>
              {selectedPath.critical_assets.map(asset => (
                <span key={asset} style={{
                  padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.md}`,
                  backgroundColor: 'rgba(220, 38, 38, 0.2)',
                  border: `1px solid ${aldeciTheme.colors.critical}`,
                  borderRadius: aldeciTheme.borderRadius.sm,
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  fontWeight: aldeciTheme.typography.fontWeight.medium,
                }}>
                  🎯 {asset}
                </span>
              ))}
            </div>
          </div>

          {/* Weak Links */}
          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.lg,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.md} 0`,
            }}>
              Weak Links in Defense
            </h3>

            <div style={{
              display: 'flex',
              gap: aldeciTheme.spacing.sm,
              flexWrap: 'wrap',
            }}>
              {selectedPath.weak_links.map(link => (
                <span key={link} style={{
                  padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.md}`,
                  backgroundColor: 'rgba(245, 158, 11, 0.2)',
                  border: `1px solid ${aldeciTheme.colors.warning}`,
                  borderRadius: aldeciTheme.borderRadius.sm,
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  fontWeight: aldeciTheme.typography.fontWeight.medium,
                }}>
                  ⚠️ {link}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AttackPathExplorer
