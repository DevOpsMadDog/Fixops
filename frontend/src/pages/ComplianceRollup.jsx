import React, { useState, useEffect } from 'react'
import aldeciTheme from '../theme/aldeci'

const ComplianceRollup = () => {
  const [complianceData, setComplianceData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selectedFramework, setSelectedFramework] = useState('SOC2')

  useEffect(() => {
    loadComplianceData()
  }, [])

  const loadComplianceData = async () => {
    try {
      const response = await fetch('/api/v1/ui/compliance')
      if (response.ok) {
        const data = await response.json()
        setComplianceData(data)
      } else {
        setComplianceData(generateDemoComplianceData())
      }
    } catch (error) {
      console.error('Failed to load compliance data:', error)
      setComplianceData(generateDemoComplianceData())
    } finally {
      setLoading(false)
    }
  }

  const generateDemoComplianceData = () => {
    return {
      frameworks: {
        SOC2: {
          name: 'SOC 2 Type II',
          total_controls: 64,
          covered_controls: 52,
          gaps: 12,
          coverage_percentage: 81.25,
          controls: [
            {
              id: 'CC8.1',
              name: 'Vulnerability Management',
              description: 'The entity implements detection policies, procedures, and tools to identify anomalies',
              status: 'covered',
              findings: 3,
              last_assessed: '2025-10-15',
            },
            {
              id: 'CC7.2',
              name: 'System Monitoring',
              description: 'The entity monitors system components and the operation of those components',
              status: 'covered',
              findings: 1,
              last_assessed: '2025-10-20',
            },
            {
              id: 'CC6.1',
              name: 'Logical and Physical Access Controls',
              description: 'The entity implements logical access security software, infrastructure, and architectures',
              status: 'gap',
              findings: 8,
              last_assessed: '2025-09-30',
            },
            {
              id: 'CC5.2',
              name: 'Risk Assessment Process',
              description: 'The entity assesses risks to the achievement of its objectives',
              status: 'covered',
              findings: 2,
              last_assessed: '2025-10-25',
            },
          ],
        },
        ISO27001: {
          name: 'ISO 27001:2022',
          total_controls: 93,
          covered_controls: 78,
          gaps: 15,
          coverage_percentage: 83.87,
          controls: [
            {
              id: 'A.12.6.1',
              name: 'Management of Technical Vulnerabilities',
              description: 'Information about technical vulnerabilities shall be obtained in a timely fashion',
              status: 'covered',
              findings: 5,
              last_assessed: '2025-10-18',
            },
            {
              id: 'A.18.2.2',
              name: 'Compliance with Security Policies',
              description: 'Managers shall regularly review compliance with security policies',
              status: 'covered',
              findings: 2,
              last_assessed: '2025-10-22',
            },
            {
              id: 'A.8.8',
              name: 'Management of Technical Vulnerabilities',
              description: 'Technical vulnerabilities shall be identified and appropriate measures taken',
              status: 'gap',
              findings: 12,
              last_assessed: '2025-09-28',
            },
          ],
        },
        'PCI-DSS': {
          name: 'PCI DSS v4.0',
          total_controls: 362,
          covered_controls: 298,
          gaps: 64,
          coverage_percentage: 82.32,
          controls: [
            {
              id: '6.2',
              name: 'Ensure All System Components are Protected from Known Vulnerabilities',
              description: 'Install vendor-supplied security patches within one month of release',
              status: 'gap',
              findings: 15,
              last_assessed: '2025-10-10',
            },
            {
              id: '11.3',
              name: 'External and Internal Vulnerability Scans',
              description: 'Perform internal and external network vulnerability scans',
              status: 'covered',
              findings: 4,
              last_assessed: '2025-10-20',
            },
            {
              id: '6.5',
              name: 'Address Common Coding Vulnerabilities',
              description: 'Develop applications based on secure coding guidelines',
              status: 'covered',
              findings: 6,
              last_assessed: '2025-10-15',
            },
          ],
        },
        GDPR: {
          name: 'GDPR',
          total_controls: 99,
          covered_controls: 85,
          gaps: 14,
          coverage_percentage: 85.86,
          controls: [
            {
              id: 'Art. 32',
              name: 'Security of Processing',
              description: 'Implement appropriate technical and organizational measures',
              status: 'covered',
              findings: 3,
              last_assessed: '2025-10-23',
            },
            {
              id: 'Art. 33',
              name: 'Notification of Personal Data Breach',
              description: 'Notify supervisory authority of data breaches within 72 hours',
              status: 'covered',
              findings: 1,
              last_assessed: '2025-10-25',
            },
            {
              id: 'Art. 25',
              name: 'Data Protection by Design',
              description: 'Implement data protection principles at design stage',
              status: 'gap',
              findings: 7,
              last_assessed: '2025-10-05',
            },
          ],
        },
      },
      trends: [
        { date: '2025-09-01', coverage: 78.5 },
        { date: '2025-09-15', coverage: 79.2 },
        { date: '2025-10-01', coverage: 80.1 },
        { date: '2025-10-15', coverage: 81.8 },
        { date: '2025-11-01', coverage: 82.5 },
      ],
      top_gaps: [
        {
          control: 'PCI-DSS 6.2',
          framework: 'PCI-DSS',
          findings: 15,
          severity: 'critical',
          description: 'Multiple unpatched critical vulnerabilities',
        },
        {
          control: 'ISO27001 A.8.8',
          framework: 'ISO27001',
          findings: 12,
          severity: 'high',
          description: 'Technical vulnerability management gaps',
        },
        {
          control: 'SOC2 CC6.1',
          framework: 'SOC2',
          findings: 8,
          severity: 'high',
          description: 'Access control deficiencies',
        },
        {
          control: 'GDPR Art. 25',
          framework: 'GDPR',
          findings: 7,
          severity: 'medium',
          description: 'Data protection by design gaps',
        },
      ],
    }
  }

  const getStatusColor = (status) => {
    return status === 'covered' ? aldeciTheme.colors.success : aldeciTheme.colors.danger
  }

  const getSeverityColor = (severity) => {
    return aldeciTheme.colors[severity] || aldeciTheme.colors.low
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
            Loading Compliance Data...
          </h2>
        </div>
      </div>
    )
  }

  const framework = complianceData?.frameworks[selectedFramework]

  return (
    <div style={{
      background: aldeciTheme.colors.bgPrimary,
      minHeight: '100vh',
      color: aldeciTheme.colors.textPrimary,
      padding: aldeciTheme.spacing.md,
      fontFamily: aldeciTheme.typography.fontFamily,
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
          }}>
            Compliance Dashboard
          </h1>
          <p style={{
            fontSize: aldeciTheme.typography.fontSize.base,
            color: aldeciTheme.colors.textSecondary,
            margin: `${aldeciTheme.spacing.xs} 0 0 0`,
          }}>
            Framework coverage and control mapping
          </p>
        </div>

        {/* Framework Selector */}
        <div style={{
          display: 'flex',
          gap: aldeciTheme.spacing.sm,
          marginBottom: aldeciTheme.spacing.lg,
          flexWrap: 'wrap',
        }}>
          {Object.keys(complianceData.frameworks).map(key => {
            const fw = complianceData.frameworks[key]
            return (
              <button
                key={key}
                onClick={() => setSelectedFramework(key)}
                style={{
                  padding: aldeciTheme.spacing.md,
                  backgroundColor: selectedFramework === key
                    ? aldeciTheme.colors.primary
                    : aldeciTheme.colors.bgCard,
                  border: `1px solid ${selectedFramework === key ? aldeciTheme.colors.primary : aldeciTheme.colors.borderPrimary}`,
                  borderRadius: aldeciTheme.borderRadius.lg,
                  color: aldeciTheme.colors.textPrimary,
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  boxShadow: selectedFramework === key ? aldeciTheme.shadows.md : 'none',
                }}
              >
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.base,
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  marginBottom: aldeciTheme.spacing.xs,
                }}>
                  {fw.name}
                </div>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.xl,
                  fontWeight: aldeciTheme.typography.fontWeight.bold,
                  color: fw.coverage_percentage >= 80 ? aldeciTheme.colors.success : aldeciTheme.colors.warning,
                }}>
                  {fw.coverage_percentage.toFixed(1)}%
                </div>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.xs,
                  color: aldeciTheme.colors.textSecondary,
                  marginTop: aldeciTheme.spacing.xs,
                }}>
                  {fw.covered_controls}/{fw.total_controls} controls
                </div>
              </button>
            )
          })}
        </div>

        {/* Coverage Overview */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: aldeciTheme.spacing.md,
          marginBottom: aldeciTheme.spacing.lg,
        }}>
          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              color: aldeciTheme.colors.textSecondary,
              textTransform: 'uppercase',
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            }}>
              Total Controls
            </h3>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xxl,
              fontWeight: aldeciTheme.typography.fontWeight.bold,
              color: aldeciTheme.colors.textPrimary,
            }}>
              {framework.total_controls}
            </div>
          </div>

          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              color: aldeciTheme.colors.textSecondary,
              textTransform: 'uppercase',
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            }}>
              Covered Controls
            </h3>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xxl,
              fontWeight: aldeciTheme.typography.fontWeight.bold,
              color: aldeciTheme.colors.success,
            }}>
              {framework.covered_controls}
            </div>
          </div>

          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              color: aldeciTheme.colors.textSecondary,
              textTransform: 'uppercase',
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            }}>
              Control Gaps
            </h3>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xxl,
              fontWeight: aldeciTheme.typography.fontWeight.bold,
              color: aldeciTheme.colors.danger,
            }}>
              {framework.gaps}
            </div>
          </div>
        </div>

        {/* Top Gaps */}
        <div style={{
          background: aldeciTheme.colors.bgCard,
          borderRadius: aldeciTheme.borderRadius.lg,
          border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
          padding: aldeciTheme.spacing.md,
          marginBottom: aldeciTheme.spacing.lg,
          boxShadow: aldeciTheme.shadows.md,
        }}>
          <h3 style={{
            fontSize: aldeciTheme.typography.fontSize.lg,
            fontWeight: aldeciTheme.typography.fontWeight.semibold,
            margin: `0 0 ${aldeciTheme.spacing.md} 0`,
          }}>
            Top Control Gaps (All Frameworks)
          </h3>

          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: aldeciTheme.spacing.sm,
          }}>
            {complianceData.top_gaps.map((gap, index) => (
              <div
                key={index}
                style={{
                  padding: aldeciTheme.spacing.md,
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: aldeciTheme.borderRadius.md,
                  border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                }}
              >
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'start',
                  marginBottom: aldeciTheme.spacing.sm,
                }}>
                  <div>
                    <div style={{
                      fontSize: aldeciTheme.typography.fontSize.base,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      color: aldeciTheme.colors.textPrimary,
                    }}>
                      {gap.control}
                    </div>
                    <div style={{
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      color: aldeciTheme.colors.textSecondary,
                      marginTop: aldeciTheme.spacing.xs,
                    }}>
                      {gap.framework}
                    </div>
                  </div>
                  <div style={{
                    display: 'flex',
                    gap: aldeciTheme.spacing.sm,
                    alignItems: 'center',
                  }}>
                    <span style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: getSeverityColor(gap.severity),
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      textTransform: 'uppercase',
                    }}>
                      {gap.severity}
                    </span>
                    <span style={{
                      fontSize: aldeciTheme.typography.fontSize.base,
                      fontWeight: aldeciTheme.typography.fontWeight.bold,
                      color: aldeciTheme.colors.danger,
                    }}>
                      {gap.findings} findings
                    </span>
                  </div>
                </div>
                <div style={{
                  fontSize: aldeciTheme.typography.fontSize.sm,
                  color: aldeciTheme.colors.textSecondary,
                }}>
                  {gap.description}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Controls Table */}
        <div style={{
          background: aldeciTheme.colors.bgCard,
          borderRadius: aldeciTheme.borderRadius.lg,
          border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
          boxShadow: aldeciTheme.shadows.md,
          overflow: 'hidden',
        }}>
          <div style={{
            padding: aldeciTheme.spacing.md,
            borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.lg,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: 0,
            }}>
              {framework.name} Controls
            </h3>
          </div>

          {/* Table Header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '150px 1fr 120px 120px 150px',
            gap: aldeciTheme.spacing.sm,
            padding: aldeciTheme.spacing.md,
            borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            backgroundColor: 'rgba(0, 0, 0, 0.2)',
            fontSize: aldeciTheme.typography.fontSize.xs,
            fontWeight: aldeciTheme.typography.fontWeight.semibold,
            color: aldeciTheme.colors.textSecondary,
            textTransform: 'uppercase',
          }}>
            <div>Control ID</div>
            <div>Description</div>
            <div>Status</div>
            <div>Findings</div>
            <div>Last Assessed</div>
          </div>

          {/* Table Body */}
          <div style={{
            maxHeight: '600px',
            overflowY: 'auto',
          }}>
            {framework.controls.map((control, index) => (
              <div
                key={control.id}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '150px 1fr 120px 120px 150px',
                  gap: aldeciTheme.spacing.sm,
                  padding: aldeciTheme.spacing.md,
                  borderBottom: index < framework.controls.length - 1 ? `1px solid ${aldeciTheme.colors.borderPrimary}` : 'none',
                  fontSize: aldeciTheme.typography.fontSize.sm,
                }}
              >
                <div style={{
                  fontWeight: aldeciTheme.typography.fontWeight.semibold,
                  color: aldeciTheme.colors.textPrimary,
                }}>
                  {control.id}
                </div>
                <div>
                  <div style={{
                    fontWeight: aldeciTheme.typography.fontWeight.medium,
                    color: aldeciTheme.colors.textPrimary,
                    marginBottom: aldeciTheme.spacing.xs,
                  }}>
                    {control.name}
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                  }}>
                    {control.description}
                  </div>
                </div>
                <div>
                  <span style={{
                    padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                    backgroundColor: getStatusColor(control.status),
                    borderRadius: aldeciTheme.borderRadius.sm,
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    fontWeight: aldeciTheme.typography.fontWeight.semibold,
                    textTransform: 'uppercase',
                  }}>
                    {control.status}
                  </span>
                </div>
                <div style={{
                  fontWeight: aldeciTheme.typography.fontWeight.bold,
                  color: control.findings > 5 ? aldeciTheme.colors.danger : aldeciTheme.colors.textPrimary,
                }}>
                  {control.findings}
                </div>
                <div style={{
                  color: aldeciTheme.colors.textSecondary,
                  fontSize: aldeciTheme.typography.fontSize.xs,
                }}>
                  {control.last_assessed}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default ComplianceRollup
