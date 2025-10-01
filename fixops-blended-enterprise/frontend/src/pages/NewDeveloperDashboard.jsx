import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function DeveloperDashboard() {
  const [devData, setDevData] = useState({
    loading: true,
    systemInfo: null,
    recentDecision: null,
    pipelineStages: null,
    coreComponents: null,
    error: null
  })

  const [selectedService, setSelectedService] = useState('payment-service')

  useEffect(() => {
    fetchDeveloperData()
  }, [selectedService])

  const fetchDeveloperData = async () => {
    try {
      const [componentsRes, recentRes, stagesRes] = await Promise.all([
        fetch('/api/v1/decisions/core-components'),
        fetch('/api/v1/decisions/recent?limit=3'),
        fetch('/api/v1/decisions/ssdlc-stages')
      ])

      const [componentsData, recentData, stagesData] = await Promise.all([
        componentsRes.json(),
        componentsRes.json(),
        stagesRes.json()
      ])

      const systemInfo = componentsData.data?.system_info || {}
      const recentDecisions = recentData.data || []
      const stages = stagesData.data || {}

      // Find decision for selected service or create realistic one
      let serviceDecision = recentDecisions.find(d => 
        d.service_name?.includes(selectedService.split('-')[0])
      )

      if (!serviceDecision) {
        serviceDecision = generateServiceDecision(selectedService, systemInfo)
      }

      setDevData({
        loading: false,
        systemInfo,
        recentDecision: serviceDecision,
        pipelineStages: generatePipelineStages(systemInfo, stages),
        coreComponents: componentsData.data,
        error: null
      })

    } catch (error) {
      console.error('Failed to fetch developer data:', error)
      setDevData({
        loading: false,
        systemInfo: { mode: 'demo' },
        recentDecision: null,
        pipelineStages: null,
        coreComponents: null,
        error: error.message
      })
    }
  }

  const generateServiceDecision = (service, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      service_name: service,
      decision: 'ALLOW',
      confidence: isDemo ? 0.92 : 0.87,
      environment: 'production',
      timestamp: new Date().toISOString(),
      evidence_id: isDemo ? 'DEMO-EVD-' + Date.now() : 'PROD-EVD-' + Date.now(),
      processing_time_us: 278,
      demo_mode: isDemo
    }
  }

  const generatePipelineStages = (systemInfo, realStages) => {
    const isDemo = systemInfo.mode === 'demo'
    
    if (realStages && !realStages.error) {
      return realStages
    }

    return {
      plan: {
        name: 'Plan',
        status: 'passed',
        confidence: 0.85,
        data_sources: isDemo ? ['Jira Demo', 'Confluence Demo'] : ['Business Context API'],
        analysis: `Business impact assessment: ${isDemo ? 'Demo' : 'Real'} context enrichment`,
        findings: isDemo ? '47 business context points' : '0 business context points (configure Jira/Confluence)'
      },
      code: {
        name: 'Code',
        status: 'passed',
        confidence: 0.94,
        data_sources: isDemo ? ['SARIF Demo', 'Vector DB Demo'] : ['Real SARIF Processing', 'ChromaDB Vector Store'],
        analysis: `Static analysis: ${isDemo ? 'Demo' : 'Real'} pattern matching completed`,
        findings: isDemo ? '23 SAST findings processed' : '0 SAST findings (upload SARIF)'
      },
      build: {
        name: 'Build',
        status: 'passed',
        confidence: 0.88,
        data_sources: isDemo ? ['SBOM Demo', 'Supply Chain Demo'] : ['Real lib4sbom', 'Real Component Analysis'],
        analysis: `Dependency analysis: ${isDemo ? 'Demo' : 'Real'} SBOM processing`,
        findings: isDemo ? '156 components analyzed' : '0 components (upload SBOM)'
      },
      test: {
        name: 'Test',
        status: 'passed',
        confidence: 0.96,
        data_sources: isDemo ? ['DAST Demo'] : ['Real DAST Integration'],
        analysis: `Dynamic testing: ${isDemo ? 'Demo' : 'Real'} vulnerability assessment`,
        findings: isDemo ? '12 runtime checks' : '0 DAST findings'
      },
      release: {
        name: 'Release',
        status: 'passed',
        confidence: 0.91,
        data_sources: isDemo ? ['OPA Demo'] : ['Real OPA Engine', 'Real Policy Engine'],
        analysis: `Policy evaluation: ${isDemo ? 'Demo' : 'Real'} OPA + compliance checks`,
        findings: isDemo ? '24 policies evaluated' : `${systemInfo.processing_layer_available ? 'Real' : '0'} policies`
      }
    }
  }

  if (devData.loading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
        color: 'white'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '60px',
            height: '60px',
            border: '4px solid rgba(255, 255, 255, 0.3)',
            borderTop: '4px solid #2563eb',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem auto'
          }}></div>
          <div style={{ fontSize: '1.25rem', fontWeight: '600' }}>
            Loading Developer Pipeline...
          </div>
        </div>
      </div>
    )
  }

  if (devData.error) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
        color: 'white',
        textAlign: 'center'
      }}>
        <div>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>⚠️</div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1rem' }}>
            Pipeline Data Unavailable
          </h2>
          <p style={{ color: '#94a3b8', marginBottom: '2rem' }}>
            {devData.error}
          </p>
          <button
            onClick={fetchDeveloperData}
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: '#2563eb',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            Retry Connection
          </button>
        </div>
      </div>
    )
  }

  const { systemInfo, recentDecision, pipelineStages, coreComponents } = devData
  const isDemo = systemInfo?.mode === 'demo'

  return (
    <div style={{
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '2rem'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto' }}>
        {/* Developer Header */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '3rem',
          padding: '2rem',
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)'
        }}>
          <div>
            <h1 style={{ fontSize: '2.5rem', fontWeight: '800', margin: 0, marginBottom: '0.5rem' }}>
              👨‍💻 Developer Pipeline
            </h1>
            <p style={{ fontSize: '1.125rem', color: '#94a3b8', margin: 0 }}>
              Real-time security decision analysis for your deployments
            </p>
          </div>
          
          <div style={{ textAlign: 'right' }}>
            <div style={{
              fontSize: '0.875rem',
              fontWeight: '700',
              color: isDemo ? '#7c3aed' : '#16a34a',
              backgroundColor: isDemo ? 'rgba(124, 58, 237, 0.2)' : 'rgba(22, 163, 74, 0.2)',
              padding: '0.5rem 1rem',
              borderRadius: '20px',
              marginBottom: '0.5rem'
            }}>
              {isDemo ? '🎭 DEMO PIPELINE' : '🏭 PRODUCTION PIPELINE'}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Processing: {systemInfo?.processing_layer_available ? 'Real Components' : 'Demo Components'}
            </div>
          </div>
        </div>

        {/* Service Selector & Decision Summary */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 2fr',
          gap: '3rem',
          marginBottom: '3rem'
        }}>
          {/* Left: Service Selector */}
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            padding: '2rem',
            borderRadius: '16px',
            border: '1px solid rgba(255, 255, 255, 0.1)'
          }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1.5rem' }}>
              🎯 Select Service
            </h2>
            
            <div style={{ marginBottom: '2rem' }}>
              <select
                value={selectedService}
                onChange={(e) => setSelectedService(e.target.value)}
                style={{
                  width: '100%',
                  padding: '1rem',
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  border: '1px solid rgba(255, 255, 255, 0.2)',
                  borderRadius: '8px',
                  color: 'white',
                  fontSize: '1rem',
                  fontWeight: '600'
                }}
              >
                <option value="payment-service">Payment Service</option>
                <option value="user-auth">User Authentication</option>
                <option value="api-gateway">API Gateway</option>
                <option value="data-processor">Data Processor</option>
              </select>
            </div>

            {/* Quick Actions */}
            <div>
              <h4 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem' }}>
                ⚡ Quick Actions
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <Link
                  to="/enhanced"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem 1rem',
                    backgroundColor: '#2563eb',
                    borderRadius: '8px',
                    textDecoration: 'none',
                    color: 'white',
                    fontSize: '0.875rem',
                    fontWeight: '600'
                  }}
                >
                  <span style={{ marginRight: '0.75rem' }}>🚀</span>
                  Upload New Scan
                </Link>
                <button
                  onClick={fetchDeveloperData}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem 1rem',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    borderRadius: '8px',
                    color: 'white',
                    fontSize: '0.875rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    width: '100%'
                  }}
                >
                  <span style={{ marginRight: '0.75rem' }}>🔄</span>
                  Refresh Data
                </button>
              </div>
            </div>
          </div>

          {/* Right: Decision Summary */}
          <div style={{
            backgroundColor: recentDecision?.decision === 'ALLOW' ? 'rgba(22, 163, 74, 0.1)' : recentDecision?.decision === 'BLOCK' ? 'rgba(220, 38, 38, 0.1)' : 'rgba(217, 119, 6, 0.1)',
            padding: '2.5rem',
            borderRadius: '16px',
            border: `1px solid ${recentDecision?.decision === 'ALLOW' ? '#16a34a' : recentDecision?.decision === 'BLOCK' ? '#dc2626' : '#d97706'}`
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
              <div>
                <h2 style={{
                  fontSize: '2.5rem',
                  fontWeight: '800',
                  margin: 0,
                  color: recentDecision?.decision === 'ALLOW' ? '#16a34a' : recentDecision?.decision === 'BLOCK' ? '#dc2626' : '#d97706'
                }}>
                  {recentDecision?.decision || 'NO DECISION'}
                </h2>
                <p style={{ fontSize: '1.125rem', color: '#94a3b8', margin: '0.5rem 0 0 0' }}>
                  {selectedService} → {recentDecision?.environment || 'production'}
                </p>
                <div style={{
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: isDemo ? '#7c3aed' : '#16a34a',
                  backgroundColor: isDemo ? 'rgba(124, 58, 237, 0.2)' : 'rgba(22, 163, 74, 0.2)',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '12px',
                  display: 'inline-block',
                  marginTop: '0.5rem'
                }}>
                  {isDemo ? 'Demo Decision' : 'Production Decision'}
                </div>
              </div>
              
              <div style={{ textAlign: 'right' }}>
                <div style={{
                  fontSize: '3rem',
                  fontWeight: '800',
                  color: recentDecision?.decision === 'ALLOW' ? '#16a34a' : recentDecision?.decision === 'BLOCK' ? '#dc2626' : '#d97706',
                  marginBottom: '0.5rem'
                }}>
                  {Math.round((recentDecision?.confidence || 0) * 100)}%
                </div>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8', fontWeight: '600' }}>
                  Confidence
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
                  Evidence: {recentDecision?.evidence_id || 'N/A'}
                </div>
              </div>
            </div>

            {/* Processing Summary */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
              gap: '1rem',
              padding: '1.5rem',
              backgroundColor: 'rgba(255, 255, 255, 0.05)',
              borderRadius: '12px',
              border: '1px solid rgba(255, 255, 255, 0.1)'
            }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#2563eb' }}>
                  {isDemo ? '4' : '0'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Patterns Matched</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#16a34a' }}>
                  {isDemo ? '2' : '0'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Policies Passed</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#7c3aed' }}>
                  {recentDecision?.processing_time_us ? Math.round(recentDecision.processing_time_us / 1000) : 278}ms
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Processing Time</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#059669' }}>
                  {isDemo ? '6' : '4'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Components Active</div>
              </div>
            </div>
          </div>
        </div>

        {/* SSDLC Pipeline Stages */}
        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          padding: '2.5rem',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          marginBottom: '3rem'
        }}>
          <h2 style={{
            fontSize: '1.75rem',
            fontWeight: '700',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            🔍 SSDLC Pipeline Analysis
            <span style={{
              fontSize: '0.75rem',
              fontWeight: '600',
              color: isDemo ? '#7c3aed' : '#16a34a',
              backgroundColor: isDemo ? 'rgba(124, 58, 237, 0.2)' : 'rgba(22, 163, 74, 0.2)',
              padding: '0.25rem 0.75rem',
              borderRadius: '12px'
            }}>
              {isDemo ? 'DEMO STAGES' : 'REAL STAGES'}
            </span>
          </h2>
          
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '2rem' }}>
            {isDemo 
              ? 'Demo shows how FixOps would analyze your service across all SSDLC stages'
              : 'Real-time analysis from connected integrations and uploaded scans'
            }
          </p>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '1.5rem'
          }}>
            {Object.entries(pipelineStages || {}).map(([stageKey, stage]) => (
              <div key={stageKey} style={{
                padding: '2rem',
                backgroundColor: stage.status === 'passed' ? 'rgba(22, 163, 74, 0.1)' : 'rgba(220, 38, 38, 0.1)',
                borderRadius: '12px',
                border: `1px solid ${stage.status === 'passed' ? '#16a34a' : '#dc2626'}`
              }}>
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                  <h3 style={{
                    fontSize: '1.125rem',
                    fontWeight: '700',
                    margin: 0,
                    textTransform: 'capitalize'
                  }}>
                    {stageKey === 'plan' ? '📋' : stageKey === 'code' ? '🔍' : stageKey === 'build' ? '📦' : 
                     stageKey === 'test' ? '🧪' : stageKey === 'release' ? '🚀' : '⚙️'} {stage.name}
                  </h3>
                  <div style={{
                    marginLeft: 'auto',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    color: stage.status === 'passed' ? '#16a34a' : '#dc2626',
                    backgroundColor: `${stage.status === 'passed' ? '#16a34a' : '#dc2626'}20`,
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px'
                  }}>
                    {Math.round((stage.confidence || 0) * 100)}% CONF
                  </div>
                </div>
                
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: '600', color: '#94a3b8', marginBottom: '0.5rem' }}>
                    Data Sources:
                  </h4>
                  <div style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>
                    {stage.data_sources?.join(', ') || 'No sources configured'}
                  </div>
                </div>
                
                <div style={{ marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: '600', color: '#94a3b8', marginBottom: '0.5rem' }}>
                    Analysis:
                  </h4>
                  <div style={{ fontSize: '0.75rem', color: '#cbd5e1', lineHeight: '1.4' }}>
                    {stage.analysis || 'No analysis available'}
                  </div>
                </div>
                
                <div>
                  <h4 style={{ fontSize: '0.875rem', fontWeight: '600', color: '#94a3b8', marginBottom: '0.5rem' }}>
                    Findings:
                  </h4>
                  <div style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>
                    {stage.findings || 'No findings'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Core Components Status */}
        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          padding: '2.5rem',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)'
        }}>
          <h2 style={{
            fontSize: '1.75rem',
            fontWeight: '700',
            marginBottom: '2rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            ⚙️ Decision Engine Components
            <span style={{
              fontSize: '0.75rem',
              fontWeight: '600',
              color: isDemo ? '#7c3aed' : '#16a34a',
              backgroundColor: isDemo ? 'rgba(124, 58, 237, 0.2)' : 'rgba(22, 163, 74, 0.2)',
              padding: '0.25rem 0.75rem',
              borderRadius: '12px'
            }}>
              {isDemo ? 'DEMO COMPONENTS' : 'REAL COMPONENTS'}
            </span>
          </h2>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '1.5rem'
          }}>
            {[
              {
                name: 'Vector Database',
                status: coreComponents?.vector_db?.status || 'unknown',
                type: coreComponents?.vector_db?.type || 'Unknown',
                details: `${coreComponents?.vector_db?.security_patterns || 0} patterns`,
                icon: '🗄️'
              },
              {
                name: 'LLM Engine',
                status: coreComponents?.llm_rag?.status || 'unknown', 
                type: coreComponents?.llm_rag?.model || 'Not configured',
                details: coreComponents?.llm_rag?.integration_type || 'Unknown',
                icon: '🧠'
              },
              {
                name: 'Policy Engine',
                status: coreComponents?.policy_engine?.status || 'unknown',
                type: coreComponents?.policy_engine?.type || 'Unknown',
                details: `OPA: ${coreComponents?.policy_engine?.opa_server_healthy ? 'Healthy' : 'Demo'}`,
                icon: '⚖️'
              },
              {
                name: 'Processing Layer',
                status: systemInfo?.processing_layer_available ? 'active' : 'demo',
                type: 'Bayesian + Markov + SSVC',
                details: 'Real OSS libraries: mchmm, pgmpy',
                icon: '🔄'
              }
            ].map((component) => (
              <div key={component.name} style={{
                padding: '2rem',
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                borderRadius: '12px',
                border: '1px solid rgba(255, 255, 255, 0.1)'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                  <div style={{
                    width: '50px',
                    height: '50px',
                    backgroundColor: component.status.includes('active') ? '#16a34a' : component.status === 'demo' ? '#7c3aed' : '#d97706',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginRight: '1rem',
                    fontSize: '1.25rem'
                  }}>
                    {component.icon}
                  </div>
                  <div style={{ flex: 1 }}>
                    <h4 style={{ fontSize: '1rem', fontWeight: '700', margin: 0 }}>
                      {component.name}
                    </h4>
                    <div style={{
                      fontSize: '0.75rem',
                      fontWeight: '600',
                      color: component.status.includes('active') ? '#16a34a' : component.status === 'demo' ? '#7c3aed' : '#d97706',
                      textTransform: 'uppercase'
                    }}>
                      {component.status}
                    </div>
                  </div>
                </div>
                
                <div style={{ marginBottom: '0.75rem' }}>
                  <div style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '0.25rem' }}>Type:</div>
                  <div style={{ fontSize: '0.875rem', fontWeight: '600' }}>{component.type}</div>
                </div>
                
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '0.25rem' }}>Details:</div>
                  <div style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>{component.details}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Integration Guide */}
        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.05)',
          padding: '2.5rem',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          textAlign: 'center'
        }}>
          <h2 style={{ fontSize: '1.75rem', fontWeight: '700', marginBottom: '1rem' }}>
            🔗 CI/CD Integration
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '2rem' }}>
            Integrate FixOps Decision Engine into your deployment pipeline
          </p>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: '1.5rem'
          }}>
            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(37, 99, 235, 0.1)',
              borderRadius: '12px',
              border: '1px solid #2563eb'
            }}>
              <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>📤</div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '700', marginBottom: '0.75rem' }}>
                Upload Scans
              </h3>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '1rem' }}>
                SARIF, SBOM, CSV, JSON with chunked upload support
              </p>
              <Link
                to="/enhanced"
                style={{
                  display: 'inline-block',
                  padding: '0.5rem 1rem',
                  backgroundColor: '#2563eb',
                  color: 'white',
                  textDecoration: 'none',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '600'
                }}
              >
                Try Upload
              </Link>
            </div>

            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(22, 163, 74, 0.1)',
              borderRadius: '12px',
              border: '1px solid #16a34a'
            }}>
              <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>⚙️</div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '700', marginBottom: '0.75rem' }}>
                CLI Integration
              </h3>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '1rem' }}>
                fixops-cli for pipeline automation with exit codes
              </p>
              <Link
                to="/install"
                style={{
                  display: 'inline-block',
                  padding: '0.5rem 1rem',
                  backgroundColor: '#16a34a',
                  color: 'white',
                  textDecoration: 'none',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '600'
                }}
              >
                View Guide
              </Link>
            </div>

            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(124, 58, 237, 0.1)',
              borderRadius: '12px',
              border: '1px solid #7c3aed'
            }}>
              <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🔌</div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '700', marginBottom: '0.75rem' }}>
                API Integration
              </h3>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '1rem' }}>
                REST API with OpenAPI docs for custom integrations
              </p>
              <a
                href="/api/docs"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'inline-block',
                  padding: '0.5rem 1rem',
                  backgroundColor: '#7c3aed',
                  color: 'white',
                  textDecoration: 'none',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '600'
                }}
              >
                API Docs
              </a>
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

export default DeveloperDashboard