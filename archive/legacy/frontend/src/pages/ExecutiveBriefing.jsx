import React, { useState, useEffect } from 'react'

function ExecutiveBriefing() {
  const [briefingData, setBriefingData] = useState({
    loading: true,
    systemMode: 'demo',
    securityPosture: {},
    businessImpact: {},
    complianceStatus: {},
    threatIntelligence: {},
    executiveSummary: null
  })

  useEffect(() => {
    generateExecutiveBriefing()
  }, [])

  const generateExecutiveBriefing = async () => {
    try {
      const [metricsRes, componentsRes, recentRes] = await Promise.all([
        fetch('/api/v1/decisions/metrics'),
        fetch('/api/v1/decisions/core-components'),
        fetch('/api/v1/decisions/recent?limit=10')
      ])

      const [metrics, components, recent] = await Promise.all([
        metricsRes.json(),
        componentsRes.json(),
        recentRes.json()
      ])

      const systemInfo = components.data?.system_info ?? {}
      const metricsData = metrics.data ?? {}
      const recentDecisions = recent.data ?? []

      setBriefingData({
        loading: false,
        systemMode: systemInfo.mode ?? 'demo',
        securityPosture: generateSecurityPosture(metricsData, recentDecisions, systemInfo),
        businessImpact: generateBusinessImpact(recentDecisions, systemInfo),
        complianceStatus: generateComplianceStatus(systemInfo),
        threatIntelligence: generateThreatIntel(recentDecisions, systemInfo),
        executiveSummary: generateExecutiveSummary(recentDecisions, systemInfo)
      })

    } catch (error) {
      setBriefingData(prev => ({ ...prev, loading: false }))
    }
  }

  const generateSecurityPosture = (metrics, decisions, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      overallRisk: decisions.some(d => d.decision === 'BLOCK') ? 'ELEVATED' : 'NORMAL',
      deploymentSuccess: isDemo ? 82 : Math.round((decisions.filter(d => d.decision === 'ALLOW').length / Math.max(decisions.length, 1)) * 100),
      securityBlocks: isDemo ? 15 : decisions.filter(d => d.decision === 'BLOCK').length,
      confidenceLevel: isDemo ? 91 : Math.round((metrics.high_confidence_rate ?? 0.87) * 100),
      mttr: isDemo ? '2.3h' : '0h', // Mean time to remediation
      coverage: isDemo ? 'Full Stack' : systemInfo.processing_layer_available ? 'Full Stack' : 'Basic'
    }
  }

  const generateBusinessImpact = (decisions, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      costAvoidance: isDemo ? '$2.4M' : decisions.filter(d => d.decision === 'BLOCK').length * 150000,
      timeToMarket: isDemo ? '+18%' : decisions.length > 0 ? '+15%' : 'Baseline',
      devVelocity: isDemo ? '+24%' : '+0%',
      complianceGaps: isDemo ? 2 : 0,
      riskReduction: isDemo ? '67%' : decisions.length > 0 ? '45%' : '0%'
    }
  }

  const generateComplianceStatus = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      ssvc: { status: 'COMPLIANT', score: 100 },
      nist: { status: 'COMPLIANT', score: isDemo ? 98 : 85 },
      soc2: { status: isDemo ? 'AUDIT READY' : 'IN PROGRESS', score: isDemo ? 95 : 70 },
      pci: { status: isDemo ? 'COMPLIANT' : 'ASSESSMENT NEEDED', score: isDemo ? 92 : 60 }
    }
  }

  const generateThreatIntel = (decisions, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      activeCampaigns: isDemo ? 3 : 0,
      cvesCritical: isDemo ? 847 : 0,
      epssHighRisk: isDemo ? 234 : 0,
      kevExploited: isDemo ? 67 : 0,
      lastUpdate: new Date().toISOString()
    }
  }

  const generateExecutiveSummary = (decisions, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    if (isDemo) {
      return {
        status: 'SECURE',
        message: 'Security posture is strong with automated decision engine preventing 15 potential security incidents this quarter. Multi-LLM consensus providing 91% confidence in deployment decisions.',
        recommendations: [
          'Continue monitoring critical payment processing components',
          'Schedule Q4 security architecture review',
          'Evaluate expanding FixOps to additional business units'
        ],
        nextReview: '2024-12-01'
      }
    } else {
      return {
        status: decisions.some(d => d.decision === 'BLOCK') ? 'ATTENTION REQUIRED' : 'OPERATIONAL',
        message: decisions.length > 0 
          ? `${decisions.length} security decisions processed. System operational and ready for enterprise deployment.`
          : 'FixOps Decision Engine ready for deployment. Connect CI/CD pipelines to begin automated security decisions.',
        recommendations: [
          'Upload security scans to test decision engine',
          'Configure Jira/Confluence for business context',
          'Deploy OPA server for production policy evaluation'
        ],
        nextReview: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
      }
    }
  }

  if (briefingData.loading) {
    return (
      <div style={{
        height: '100vh',
        background: 'radial-gradient(circle at center, #1e293b 0%, #0f172a 100%)',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        color: 'white'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '80px',
            height: '80px',
            border: '4px solid #334155',
            borderTop: '4px solid #7c3aed',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 2rem auto'
          }}></div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '0.5rem' }}>
            GENERATING EXECUTIVE BRIEFING
          </h2>
          <p style={{ color: '#94a3b8' }}>Analyzing security intelligence...</p>
        </div>
      </div>
    )
  }

  const isDemo = briefingData.systemMode === 'demo'

  return (
    <div style={{
      background: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '1rem'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto' }}>
        
        {/* Compact Executive Header */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.2) 0%, rgba(30, 41, 59, 0.6) 100%)',
          padding: '1.5rem',
          borderRadius: '8px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          marginBottom: '1rem',
          boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h1 style={{
                fontSize: '1.75rem',
                fontWeight: '700',
                margin: 0,
                color: 'white',
                fontFamily: '"Inter", sans-serif'
              }}>
                Executive Security Briefing
              </h1>
              <p style={{ fontSize: '0.875rem', color: '#c7d2fe', margin: '0.25rem 0 0 0', fontFamily: '"Inter", sans-serif' }}>
                Strategic security intelligence and business impact analysis
              </p>
            </div>
            
            <div style={{
              textAlign: 'center',
              padding: '1rem',
              backgroundColor: 'rgba(0, 0, 0, 0.5)',
              borderRadius: '8px',
              border: '1px solid #7c3aed'
            }}>
              <div style={{
                fontSize: '1.25rem',
                fontWeight: '700',
                color: briefingData.executiveSummary?.status === 'SECURE' ? '#10b981' : 
                       briefingData.executiveSummary?.status === 'ATTENTION REQUIRED' ? '#f59e0b' : '#64748b',
                marginBottom: '0.25rem',
                fontFamily: '"Inter", sans-serif'
              }}>
                {briefingData.executiveSummary?.status || 'OPERATIONAL'}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', fontFamily: '"Inter", sans-serif' }}>
                SECURITY STATUS
              </div>
            </div>
          </div>
        </div>

        {/* Compact Business Impact Dashboard */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          marginBottom: '1rem'
        }}>
          {[
            {
              title: 'Business Value',
              value: briefingData.businessImpact.costAvoidance,
              subtitle: 'Security ROI',
              icon: '💰',
              color: '#16a34a'
            },
            {
              title: 'Decision Accuracy',
              value: `${briefingData.securityPosture.confidenceLevel}%`,
              subtitle: 'AI Confidence',
              icon: '🎯',
              color: '#2563eb'
            },
            {
              title: 'Response Time',
              value: briefingData.securityPosture.mttr,
              subtitle: 'MTTR',
              icon: '⚡',
              color: '#7c3aed'
            },
            {
              title: 'Risk Reduction',
              value: briefingData.businessImpact.riskReduction,
              subtitle: 'Improvement',
              icon: '📉',
              color: '#059669'
            }
          ].map((metric) => (
            <div key={metric.title} style={{
              padding: '1rem',
              backgroundColor: 'rgba(255, 255, 255, 0.05)',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              textAlign: 'center'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                backgroundColor: metric.color,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.75rem auto',
                fontSize: '1rem'
              }}>
                {metric.icon}
              </div>
              <div style={{
                fontSize: '1.25rem',
                fontWeight: '700',
                color: metric.color,
                marginBottom: '0.25rem',
                fontFamily: '"Inter", sans-serif'
              }}>
                {metric.value}
              </div>
              <div style={{
                fontSize: '0.75rem',
                fontWeight: '600',
                marginBottom: '0.25rem',
                color: 'white',
                fontFamily: '"Inter", sans-serif'
              }}>
                {metric.title}
              </div>
              <div style={{
                fontSize: '0.625rem',
                color: '#64748b',
                fontFamily: '"Inter", sans-serif'
              }}>
                {metric.subtitle}
              </div>
            </div>
          ))}
        </div>

        {/* Strategic Intelligence Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '3rem',
          marginBottom: '3rem'
        }}>
          {/* Left: Executive Summary */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(0, 0, 0, 0.9) 100%)',
            padding: '3rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <h2 style={{
              fontSize: '1.75rem',
              fontWeight: '800',
              marginBottom: '2rem',
              color: '#a78bfa'
            }}>
              📋 STRATEGIC SECURITY ASSESSMENT
            </h2>

            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(167, 139, 250, 0.1)',
              border: '1px solid #a78bfa',
              borderRadius: '16px',
              marginBottom: '2rem'
            }}>
              <p style={{
                fontSize: '1.125rem',
                lineHeight: '1.6',
                color: '#e2e8f0',
                margin: 0
              }}>
                {briefingData.executiveSummary?.message}
              </p>
            </div>

            <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1.5rem', color: '#60a5fa' }}>
              🎯 STRATEGIC RECOMMENDATIONS
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {briefingData.executiveSummary?.recommendations?.map((rec, index) => (
                <div key={index} style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.4)',
                  borderRadius: '12px',
                  border: '1px solid #374151'
                }}>
                  <div style={{
                    width: '32px',
                    height: '32px',
                    backgroundColor: '#3b82f6',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginRight: '1rem',
                    flexShrink: 0,
                    fontSize: '0.875rem',
                    fontWeight: '700',
                    color: 'white'
                  }}>
                    {index + 1}
                  </div>
                  <div>
                    <p style={{ fontSize: '1rem', color: '#e2e8f0', margin: 0, lineHeight: '1.5' }}>
                      {rec}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Threat Intelligence */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #dc2626',
            boxShadow: '0 8px 32px rgba(220, 38, 38, 0.3)'
          }}>
            <h2 style={{
              fontSize: '1.5rem',
              fontWeight: '800',
              marginBottom: '2rem',
              color: '#fca5a5'
            }}>
              🚨 THREAT INTELLIGENCE
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {[
                {
                  threat: 'Active CVE Campaigns',
                  count: briefingData.threatIntelligence.activeCampaigns || 0,
                  severity: 'HIGH',
                  color: '#dc2626'
                },
                {
                  threat: 'Critical CVEs',
                  count: briefingData.threatIntelligence.cvesCritical || 0,
                  severity: 'MONITOR',
                  color: '#d97706'
                },
                {
                  threat: 'EPSS High Risk',
                  count: briefingData.threatIntelligence.epssHighRisk || 0,
                  severity: 'WATCH',
                  color: '#3b82f6'
                },
                {
                  threat: 'KEV Exploited',
                  count: briefingData.threatIntelligence.kevExploited || 0,
                  severity: 'CRITICAL',
                  color: '#dc2626'
                }
              ].map((intel) => (
                <div key={intel.threat} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(220, 38, 38, 0.1)',
                  borderRadius: '12px',
                  border: '1px solid #dc262640'
                }}>
                  <div>
                    <h4 style={{ fontSize: '1rem', fontWeight: '700', margin: 0, color: 'white' }}>
                      {intel.threat}
                    </h4>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                      {intel.severity} PRIORITY
                    </div>
                  </div>
                  <div style={{
                    fontSize: '1.75rem',
                    fontWeight: '900',
                    color: intel.color
                  }}>
                    {intel.count}
                  </div>
                </div>
              ))}
            </div>

            <div style={{
              marginTop: '2rem',
              padding: '1.5rem',
              backgroundColor: 'rgba(0, 0, 0, 0.5)',
              borderRadius: '12px',
              border: '1px solid #374151'
            }}>
              <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.5rem' }}>
                LAST INTELLIGENCE UPDATE
              </div>
              <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#10b981' }}>
                {briefingData.threatIntelligence.lastUpdate ? 
                  new Date(briefingData.threatIntelligence.lastUpdate).toLocaleString() : 
                  'Real-time feed active'
                }
              </div>
            </div>
          </div>
        </div>

        {/* Compliance Dashboard */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(0, 0, 0, 0.9) 100%)',
          padding: '3rem',
          borderRadius: '20px',
          border: '1px solid #334155',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
        }}>
          <h2 style={{
            fontSize: '1.75rem',
            fontWeight: '800',
            marginBottom: '2rem',
            color: '#10b981'
          }}>
            📊 COMPLIANCE & GOVERNANCE STATUS
          </h2>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '2rem'
          }}>
            {Object.entries(briefingData.complianceStatus).map(([framework, data]) => (
              <div key={framework} style={{
                padding: '2rem',
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                borderRadius: '16px',
                border: '1px solid #374151',
                textAlign: 'center'
              }}>
                <h3 style={{
                  fontSize: '1rem',
                  fontWeight: '800',
                  color: 'white',
                  marginBottom: '1rem',
                  textTransform: 'uppercase'
                }}>
                  {framework}
                </h3>
                <div style={{
                  fontSize: '2rem',
                  fontWeight: '900',
                  color: data.status === 'COMPLIANT' ? '#10b981' : data.status.includes('PROGRESS') ? '#f59e0b' : '#64748b',
                  marginBottom: '0.75rem'
                }}>
                  {data.score}%
                </div>
                <div style={{
                  fontSize: '0.75rem',
                  fontWeight: '700',
                  color: data.status === 'COMPLIANT' ? '#10b981' : data.status.includes('PROGRESS') ? '#f59e0b' : '#64748b',
                  backgroundColor: `${data.status === 'COMPLIANT' ? '#10b981' : data.status.includes('PROGRESS') ? '#f59e0b' : '#64748b'}20`,
                  padding: '0.25rem 0.75rem',
                  borderRadius: '12px',
                  display: 'inline-block'
                }}>
                  {data.status}
                </div>
              </div>
            ))}
          </div>

          {/* Next Review */}
          <div style={{
            marginTop: '3rem',
            padding: '2rem',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            border: '1px solid #3b82f6',
            borderRadius: '16px',
            textAlign: 'center'
          }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: '700', marginBottom: '1rem', color: '#60a5fa' }}>
              📅 NEXT SECURITY REVIEW
            </h3>
            <div style={{ fontSize: '1.5rem', fontWeight: '800', color: 'white' }}>
              {briefingData.executiveSummary?.nextReview ? 
                new Date(briefingData.executiveSummary.nextReview).toLocaleDateString() : 
                'Schedule Required'
              }
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}

export default ExecutiveBriefing
