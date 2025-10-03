import React, { useEffect, useState } from 'react'

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
    const timer = setTimeout(() => {
      const systemInfo = { mode: 'demo' }
      const recentDecisions = buildSampleDecisions()
      const metricsData = { high_confidence_rate: 0.91 }

      setBriefingData({
        loading: false,
        systemMode: 'demo',
        securityPosture: generateSecurityPosture(metricsData, recentDecisions, systemInfo),
        businessImpact: generateBusinessImpact(recentDecisions, systemInfo),
        complianceStatus: generateComplianceStatus(systemInfo),
        threatIntelligence: generateThreatIntel(recentDecisions, systemInfo),
        executiveSummary: generateExecutiveSummary(recentDecisions, systemInfo)
      })
    }, 600)

    return () => clearTimeout(timer)
  }, [])

  const buildSampleDecisions = () => ([
    { decision: 'ALLOW', service_name: 'payments', timestamp: new Date().toISOString(), confidence: 0.94 },
    { decision: 'ALLOW', service_name: 'claims', timestamp: new Date().toISOString(), confidence: 0.9 },
    { decision: 'BLOCK', service_name: 'analytics', timestamp: new Date().toISOString(), confidence: 0.82 },
    { decision: 'ALLOW', service_name: 'customer-portal', timestamp: new Date().toISOString(), confidence: 0.93 },
    { decision: 'ALLOW', service_name: 'ml-service', timestamp: new Date().toISOString(), confidence: 0.95 }
  ])

  const generateSecurityPosture = (metrics, decisions, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'

    return {
      overallRisk: decisions.some(d => d.decision === 'BLOCK') ? 'ELEVATED' : 'NORMAL',
      deploymentSuccess: isDemo ? 82 : Math.round((decisions.filter(d => d.decision === 'ALLOW').length / Math.max(decisions.length, 1)) * 100),
      securityBlocks: isDemo ? 15 : decisions.filter(d => d.decision === 'BLOCK').length,
      confidenceLevel: isDemo ? 91 : Math.round((metrics.high_confidence_rate || 0.87) * 100),
      mttr: isDemo ? '2.3h' : '0h',
      coverage: isDemo ? 'Full Stack' : 'Core Services'
    }
  }

  const generateBusinessImpact = (decisions, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'

    return {
      costAvoidance: isDemo ? '$2.4M' : `$${decisions.filter(d => d.decision === 'BLOCK').length * 150000}`,
      timeToMarket: isDemo ? '+18%' : '+15%',
      devVelocity: isDemo ? '+24%' : '+10%',
      complianceGaps: isDemo ? 2 : 0,
      riskReduction: isDemo ? '67%' : '45%'
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
    }

    return {
      status: decisions.some(d => d.decision === 'BLOCK') ? 'ATTENTION REQUIRED' : 'OPERATIONAL',
      message: `${decisions.length} security decisions processed. System operational and ready for enterprise deployment.`,
      recommendations: [
        'Upload security scans to test decision engine',
        'Configure Jira/Confluence for business context',
        'Deploy OPA server for production policy evaluation'
      ],
      nextReview: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
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
                color: 'white'
              }}>
                Executive Security Briefing
              </h1>
              <p style={{ fontSize: '0.875rem', color: '#c7d2fe', margin: '0.25rem 0 0 0' }}>
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
              <div style={{ fontSize: '0.75rem', color: '#c4b5fd', letterSpacing: '0.1em' }}>STATUS</div>
              <div style={{ fontSize: '1.25rem', fontWeight: '700', color: '#c084fc' }}>
                {briefingData.executiveSummary?.status}
              </div>
            </div>
          </div>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '1rem',
          marginBottom: '1rem'
        }}>
          <div style={{
            background: 'rgba(30, 41, 59, 0.7)',
            borderRadius: '10px',
            border: '1px solid rgba(124, 58, 237, 0.25)',
            padding: '1.5rem'
          }}>
            <h2 style={{
              fontSize: '1.1rem',
              fontWeight: '600',
              marginBottom: '1rem',
              color: '#c084fc'
            }}>
              Security Posture Overview
            </h2>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '1rem' }}>
              {Object.entries(briefingData.securityPosture).map(([key, value]) => (
                <div key={key} style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  background: 'rgba(49, 46, 129, 0.35)',
                  border: '1px solid rgba(192, 132, 252, 0.3)'
                }}>
                  <div style={{ fontSize: '0.75rem', color: '#d8b4fe', marginBottom: '0.5rem' }}>
                    {key.replace(/([A-Z])/g, ' $1').toUpperCase()}
                  </div>
                  <div style={{ fontSize: '1.5rem', fontWeight: '700', color: 'white' }}>{value}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gap: '1rem' }}>
            <div style={{
              background: 'rgba(30, 41, 59, 0.7)',
              borderRadius: '10px',
              border: '1px solid rgba(96, 165, 250, 0.3)',
              padding: '1.5rem'
            }}>
              <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '0.75rem', color: '#93c5fd' }}>
                Business Impact
              </h2>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {Object.entries(briefingData.businessImpact).map(([key, value]) => (
                  <div key={key} style={{ display: 'flex', justifyContent: 'space-between', color: '#e0e7ff' }}>
                    <span style={{ fontSize: '0.8rem' }}>{key.replace(/([A-Z])/g, ' $1')}</span>
                    <span style={{ fontWeight: '600' }}>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{
              background: 'rgba(30, 41, 59, 0.7)',
              borderRadius: '10px',
              border: '1px solid rgba(34, 197, 94, 0.3)',
              padding: '1.5rem'
            }}>
              <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '0.75rem', color: '#86efac' }}>
                Compliance Status
              </h2>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {Object.entries(briefingData.complianceStatus).map(([framework, status]) => (
                  <div key={framework} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    color: '#dcfce7'
                  }}>
                    <span style={{ fontSize: '0.8rem' }}>{framework.toUpperCase()}</span>
                    <span style={{ fontWeight: '600' }}>{status.status}</span>
                    <span>{status.score}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: '1rem'
        }}>
          <div style={{
            background: 'rgba(30, 41, 59, 0.8)',
            borderRadius: '10px',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            padding: '1.5rem'
          }}>
            <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '0.75rem', color: '#38bdf8' }}>
              Threat Intelligence
            </h2>
            <div style={{ display: 'grid', gap: '0.75rem' }}>
              {Object.entries(briefingData.threatIntelligence).map(([key, value]) => (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', color: '#bae6fd' }}>
                  <span style={{ fontSize: '0.8rem' }}>{key.replace(/([A-Z])/g, ' $1')}</span>
                  <span style={{ fontWeight: '600' }}>{key === 'lastUpdate' ? new Date(value).toLocaleString() : value}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={{
            background: 'rgba(30, 41, 59, 0.8)',
            borderRadius: '10px',
            border: '1px solid rgba(249, 115, 22, 0.3)',
            padding: '1.5rem'
          }}>
            <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '0.75rem', color: '#fb923c' }}>
              Executive Summary
            </h2>
            <p style={{ fontSize: '0.85rem', color: '#fde68a', lineHeight: 1.6 }}>
              {briefingData.executiveSummary?.message}
            </p>
            <ul style={{ fontSize: '0.8rem', color: '#fed7aa', lineHeight: 1.8 }}>
              {briefingData.executiveSummary?.recommendations.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <div style={{ fontSize: '0.75rem', color: '#f97316', marginTop: '0.75rem', fontWeight: '600' }}>
              Next Review: {briefingData.executiveSummary?.nextReview}
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
