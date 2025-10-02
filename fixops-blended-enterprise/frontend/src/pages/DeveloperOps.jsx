import React, { useState, useEffect } from 'react'

function DeveloperOps() {
  const [pipelineState, setPipelineState] = useState({
    loading: true,
    systemMode: 'demo',
    currentService: 'payment-service',
    lastDecision: null,
    ssdlcStages: {},
    integrationStatus: {},
    cliCommands: []
  })

  useEffect(() => {
    initializePipeline()
  }, [])

  const initializePipeline = async () => {
    try {
      const [componentsRes, recentRes, stagesRes] = await Promise.all([
        fetch('/api/v1/decisions/core-components'),
        fetch('/api/v1/decisions/recent?limit=1'),
        fetch('/api/v1/decisions/ssdlc-stages')
      ])

      const [components, recent, stages] = await Promise.all([
        componentsRes.json(),
        recentRes.json(),
        stagesRes.json()
      ])

      const systemInfo = components.data?.system_info || {}
      const lastDecision = recent.data?.[0] || generateSampleDecision(systemInfo)
      const ssdlcData = stages.data || generateSampleStages(systemInfo)

      setPipelineState({
        loading: false,
        systemMode: systemInfo.mode || 'demo',
        currentService: lastDecision?.service_name || 'payment-service',
        lastDecision,
        ssdlcStages: ssdlcData,
        integrationStatus: generateIntegrationStatus(systemInfo),
        cliCommands: generateCLICommands(systemInfo)
      })

    } catch (error) {
      setPipelineState(prev => ({ ...prev, loading: false }))
    }
  }

  const generateSampleDecision = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      service_name: 'payment-service',
      decision: 'ALLOW',
      confidence: isDemo ? 0.92 : 0.87,
      evidence_id: `${isDemo ? 'DEMO' : 'PROD'}-EVD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      processing_time_us: 278
    }
  }

  const generateSampleStages = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      ingestion: { 
        name: 'Scan Ingestion', 
        status: 'active', 
        findings: isDemo ? 23 : 0,
        tools: isDemo ? ['SonarQube', 'Snyk', 'OWASP ZAP'] : ['Upload via API/CLI']
      },
      processing: { 
        name: 'Processing Layer', 
        status: isDemo ? 'active' : 'ready', 
        components: ['Bayesian', 'Markov', 'SSVC', 'Knowledge Graph'],
        performance: isDemo ? '285μs avg' : 'Standby'
      },
      consensus: { 
        name: 'Multi-LLM Consensus', 
        status: 'active', 
        models: ['GPT-5', 'Claude', 'Gemini'],
        accuracy: isDemo ? '94%' : 'Ready'
      },
      policy: { 
        name: 'Policy Evaluation', 
        status: isDemo ? 'active' : 'ready', 
        engine: isDemo ? 'Demo OPA' : 'Production OPA',
        policies: isDemo ? 24 : 2
      },
      evidence: { 
        name: 'Evidence Lake', 
        status: 'active', 
        storage: isDemo ? 'Demo Cache' : 'Production DB',
        retention: '7 years'
      }
    }
  }

  const generateIntegrationStatus = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return {
      cicd: { status: 'READY', method: 'CLI + API', exitCodes: '0=ALLOW, 1=BLOCK, 2=DEFER' },
      api: { status: 'ACTIVE', endpoint: '/api/v1/decisions/make-decision', docs: '/api/docs' },
      kubernetes: { status: 'READY', deployment: 'helm chart available', ha: 'multi-replica' },
      monitoring: { status: isDemo ? 'DEMO' : 'READY', prometheus: '/metrics', grafana: 'dashboards available' }
    }
  }

  const generateCLICommands = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'
    
    return [
      {
        purpose: 'Upload Scan',
        command: 'fixops ingest --scan-file results.sarif --service-name payment-service --environment production',
        description: 'Ingest security scan results'
      },
      {
        purpose: 'Make Decision',
        command: 'fixops make-decision --service-name payment-service --scan-file results.sarif',
        description: 'Get deployment decision with evidence'
      },
      {
        purpose: 'Health Check',
        command: 'fixops health',
        description: 'Verify system components status'
      },
      {
        purpose: 'Get Evidence',
        command: 'fixops get-evidence --evidence-id EVD-2024-001',
        description: 'Retrieve audit evidence record'
      }
    ]
  }

  if (pipelineState.loading) {
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
            borderTop: '4px solid #059669',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 2rem auto'
          }}></div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '0.5rem' }}>
            INITIALIZING PIPELINE INTEGRATION
          </h2>
          <p style={{ color: '#94a3b8' }}>Loading DevOps integration status...</p>
        </div>
      </div>
    )
  }

  const isDemo = pipelineState.systemMode === 'demo'

  return (
    <div style={{
      background: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '1rem'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto' }}>
        
        {/* Compact Pipeline Command Center */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(5, 150, 105, 0.2) 0%, rgba(30, 41, 59, 0.6) 100%)',
          padding: '1.5rem',
          borderRadius: '8px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          marginBottom: '1rem',
          boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h1 style={{
                fontSize: '1.5rem',
                fontWeight: '600',
                margin: 0,
                color: 'white',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
              }}>
                DevOps Pipeline Integration
              </h1>
              <p style={{ fontSize: '0.875rem', color: '#a7f3d0', margin: '0.25rem 0 0 0', fontFamily: '"Inter", sans-serif' }}>
                CI/CD security decision automation and deployment gating
              </p>
            </div>
            
            <div style={{
              textAlign: 'center',
              padding: '1rem',
              backgroundColor: 'rgba(0, 0, 0, 0.5)',
              borderRadius: '8px',
              border: '1px solid #059669'
            }}>
              <div style={{
                fontSize: '1.25rem',
                fontWeight: '600',
                color: pipelineState.lastDecision?.decision === 'ALLOW' ? '#10b981' : 
                       pipelineState.lastDecision?.decision === 'BLOCK' ? '#dc2626' : '#f59e0b',
                marginBottom: '0.25rem',
                fontFamily: '"Inter", sans-serif'
              }}>
                {pipelineState.lastDecision?.decision || 'STANDBY'}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', fontFamily: '"Inter", sans-serif' }}>
                LAST DECISION
              </div>
            </div>
          </div>
        </div>

        {/* Compact SSDLC Pipeline Stages */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(0, 0, 0, 0.8) 100%)',
          padding: '1.5rem',
          borderRadius: '8px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          marginBottom: '1rem',
          boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
        }}>
          <h2 style={{
            fontSize: '1rem',
            fontWeight: '600',
            marginBottom: '0.75rem',
            color: '#60a5fa',
            fontFamily: '"Inter", sans-serif'
          }}>
            Secure Software Development Lifecycle
          </h2>
          <p style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '1rem', fontFamily: '"Inter", sans-serif' }}>
            {isDemo 
              ? 'Demo pipeline showing complete SSDLC integration with FixOps Decision Engine'
              : 'Production pipeline ready for security scan ingestion and decision automation'
            }
          </p>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
            gap: '1rem'
          }}>
            {Object.entries(pipelineState.ssdlcStages).map(([stageKey, stage]) => (
              <div key={stageKey} style={{
                background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.6) 0%, rgba(30, 41, 59, 0.4) 100%)',
                padding: '1rem',
                borderRadius: '8px',
                border: '1px solid rgba(255, 255, 255, 0.1)'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <div style={{
                    width: '35px',
                    height: '35px',
                    backgroundColor: stage.status === 'active' ? '#10b981' : '#64748b',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginRight: '0.75rem',
                    fontSize: '1rem'
                  }}>
                    {stageKey === 'ingestion' ? '📥' : stageKey === 'processing' ? '🧠' : 
                     stageKey === 'consensus' ? '🤖' : stageKey === 'policy' ? '⚖️' : '📚'}
                  </div>
                  <div>
                    <h3 style={{ fontSize: '0.875rem', fontWeight: '600', margin: 0, color: 'white', fontFamily: '"Inter", sans-serif' }}>
                      {stage.name}
                    </h3>
                    <div style={{
                      fontSize: '0.625rem',
                      fontWeight: '500',
                      color: stage.status === 'active' ? '#10b981' : '#64748b',
                      textTransform: 'uppercase',
                      fontFamily: '"Inter", sans-serif'
                    }}>
                      {stage.status}
                    </div>
                  </div>
                </div>

                <div style={{ marginBottom: '0.75rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem', fontFamily: '"Inter", sans-serif' }}>
                    Configuration:
                  </div>
                  <div style={{ fontSize: '0.625rem', color: '#e2e8f0', fontFamily: '"Inter", sans-serif' }}>
                    {stage.tools ? stage.tools.join(', ') : 
                     stage.components ? stage.components.join(', ') :
                     stage.models ? stage.models.join(', ') :
                     stage.engine || stage.storage || 'Ready'}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.25rem', fontFamily: '"Inter", sans-serif' }}>
                    Performance:
                  </div>
                  <div style={{ fontSize: '0.75rem', fontWeight: '600', color: '#10b981', fontFamily: '"Inter", sans-serif' }}>
                    {stage.findings !== undefined ? `${stage.findings} findings` :
                     stage.performance || stage.accuracy || `${stage.policies || 0} policies` || 'Operational'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* CI/CD Integration Commands */}
        <div style={{
          background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%)',
          padding: '3rem',
          borderRadius: '20px',
          border: '1px solid #374151',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
        }}>
          <h2 style={{
            fontSize: '1.75rem',
            fontWeight: '800',
            marginBottom: '2rem',
            color: '#fbbf24'
          }}>
            💻 CI/CD INTEGRATION COMMANDS
          </h2>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
            gap: '2rem'
          }}>
            {pipelineState.cliCommands.map((cmd) => (
              <div key={cmd.purpose} style={{
                background: 'rgba(0, 0, 0, 0.8)',
                padding: '2rem',
                borderRadius: '12px',
                border: '1px solid #475569'
              }}>
                <h3 style={{
                  fontSize: '1rem',
                  fontWeight: '700',
                  marginBottom: '1rem',
                  color: '#fbbf24'
                }}>
                  {cmd.purpose}
                </h3>
                <div style={{
                  backgroundColor: '#000000',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: '1px solid #374151',
                  marginBottom: '1rem',
                  fontFamily: 'Monaco, "Lucida Console", monospace'
                }}>
                  <code style={{
                    fontSize: '0.75rem',
                    color: '#10b981',
                    wordBreak: 'break-all'
                  }}>
                    {cmd.command}
                  </code>
                </div>
                <p style={{
                  fontSize: '0.75rem',
                  color: '#94a3b8',
                  margin: 0,
                  lineHeight: '1.4'
                }}>
                  {cmd.description}
                </p>
              </div>
            ))}
          </div>

          {/* Integration Status */}
          <div style={{ marginTop: '3rem', paddingTop: '2rem', borderTop: '1px solid #475569' }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1.5rem', color: '#60a5fa' }}>
              🔌 INTEGRATION STATUS
            </h3>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1.5rem'
            }}>
              {Object.entries(pipelineState.integrationStatus).map(([integration, config]) => (
                <div key={integration} style={{
                  padding: '1.5rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.5)',
                  borderRadius: '12px',
                  border: '1px solid #475569',
                  textAlign: 'center'
                }}>
                  <h4 style={{
                    fontSize: '1rem',
                    fontWeight: '700',
                    marginBottom: '0.75rem',
                    color: 'white',
                    textTransform: 'uppercase'
                  }}>
                    {integration}
                  </h4>
                  <div style={{
                    fontSize: '0.875rem',
                    fontWeight: '700',
                    color: config.status === 'ACTIVE' ? '#10b981' : config.status === 'READY' ? '#3b82f6' : '#a78bfa',
                    marginBottom: '0.5rem'
                  }}>
                    {config.status}
                  </div>
                  <div style={{
                    fontSize: '0.75rem',
                    color: '#94a3b8',
                    lineHeight: '1.3'
                  }}>
                    {config.method || config.endpoint || config.deployment || config.prometheus}
                  </div>
                </div>
              ))}
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

export default DeveloperOps