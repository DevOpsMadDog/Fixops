import React, { useEffect, useState } from 'react'

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
    const timer = setTimeout(() => {
      const systemInfo = { mode: 'demo' }
      const lastDecision = generateSampleDecision(systemInfo)
      const ssdlcData = generateSampleStages(systemInfo)

      setPipelineState({
        loading: false,
        systemMode: 'demo',
        currentService: lastDecision.service_name,
        lastDecision,
        ssdlcStages: ssdlcData,
        integrationStatus: generateIntegrationStatus(systemInfo),
        cliCommands: generateCLICommands(systemInfo)
      })
    }, 600)

    return () => clearTimeout(timer)
  }, [])

  const generateSampleDecision = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'

    return {
      service_name: 'payment-service',
      decision: 'ALLOW',
      confidence: isDemo ? 0.92 : 0.87,
      evidence_id: `${isDemo ? 'DEMO' : 'PROD'}-EVD-2024-001`,
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
        tools: ['SonarQube', 'Snyk', 'OWASP ZAP']
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

  const generateCLICommands = () => ([
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
  ])

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
                color: 'white'
              }}>
                DevOps Pipeline Integration
              </h1>
              <p style={{ fontSize: '0.875rem', color: '#a7f3d0', margin: '0.25rem 0 0 0' }}>
                CI/CD security decision automation and deployment gating
              </p>
            </div>

            <div style={{
              textAlign: 'right',
              fontSize: '0.75rem',
              color: '#bbf7d0'
            }}>
              <div>Current Service: {pipelineState.currentService}</div>
              <div>Last Decision: {pipelineState.lastDecision?.decision}</div>
            </div>
          </div>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '1rem'
        }}>
          <div style={{
            background: 'rgba(15, 23, 42, 0.75)',
            borderRadius: '10px',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            padding: '1.5rem'
          }}>
            <h2 style={{
              fontSize: '1rem',
              fontWeight: '600',
              marginBottom: '1rem',
              color: '#34d399'
            }}>
              SSDLC Decision Pipeline
            </h2>

            <div style={{
              display: 'grid',
              gap: '0.75rem'
            }}>
              {Object.entries(pipelineState.ssdlcStages).map(([key, stage]) => (
                <div key={key} style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  background: 'rgba(6, 78, 59, 0.4)',
                  border: '1px solid rgba(16, 185, 129, 0.3)'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                    <div>
                      <h3 style={{
                        fontSize: '0.95rem',
                        margin: 0,
                        color: '#6ee7b7'
                      }}>
                        {stage.name}
                      </h3>
                      <p style={{
                        fontSize: '0.75rem',
                        color: '#a7f3d0'
                      }}>
                        {stage.components?.join(', ') || stage.tools?.join(', ')}
                      </p>
                    </div>
                    <div style={{
                      padding: '0.25rem 0.6rem',
                      borderRadius: '9999px',
                      background: stage.status === 'active' ? 'rgba(34, 197, 94, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                      border: '1px solid rgba(34, 197, 94, 0.4)',
                      fontSize: '0.7rem',
                      color: '#34d399',
                      fontWeight: '600'
                    }}>
                      {stage.status.toUpperCase()}
                    </div>
                  </div>

                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '0.75rem',
                    color: '#99f6e4'
                  }}>
                    <span>{stage.performance || stage.storage}</span>
                    <span>{stage.throughput || stage.retention || `${stage.findings} findings`}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gap: '1rem' }}>
            <div style={{
              background: 'rgba(15, 23, 42, 0.75)',
              borderRadius: '10px',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              padding: '1.5rem'
            }}>
              <h2 style={{
                fontSize: '1rem',
                fontWeight: '600',
                marginBottom: '1rem',
                color: '#38bdf8'
              }}>
                Integration Status
              </h2>

              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {Object.entries(pipelineState.integrationStatus).map(([key, status]) => (
                  <div key={key} style={{
                    padding: '0.75rem',
                    borderRadius: '8px',
                    background: 'rgba(14, 116, 144, 0.25)',
                    border: '1px solid rgba(56, 189, 248, 0.3)'
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      marginBottom: '0.5rem'
                    }}>
                      <strong style={{ color: '#bae6fd', fontSize: '0.85rem' }}>{key.toUpperCase()}</strong>
                      <span style={{
                        padding: '0.25rem 0.5rem',
                        borderRadius: '9999px',
                        background: 'rgba(34, 211, 238, 0.2)',
                        border: '1px solid rgba(34, 211, 238, 0.4)',
                        color: '#22d3ee',
                        fontSize: '0.7rem',
                        fontWeight: '600'
                      }}>
                        {status.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#e0f2fe', lineHeight: 1.6 }}>
                      {status.method && <div><strong>Method:</strong> {status.method}</div>}
                      {status.endpoint && <div><strong>Endpoint:</strong> {status.endpoint}</div>}
                      {status.deployment && <div><strong>Deployment:</strong> {status.deployment}</div>}
                      {status.ha && <div><strong>High Availability:</strong> {status.ha}</div>}
                      {status.prometheus && <div><strong>Prometheus:</strong> {status.prometheus}</div>}
                      {status.grafana && <div><strong>Grafana:</strong> {status.grafana}</div>}
                      {status.exitCodes && <div><strong>Exit Codes:</strong> {status.exitCodes}</div>}
                      {status.docs && <div><strong>Docs:</strong> {status.docs}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{
              background: 'rgba(15, 23, 42, 0.85)',
              borderRadius: '10px',
              border: '1px solid rgba(99, 102, 241, 0.25)',
              padding: '1.5rem'
            }}>
              <h2 style={{
                fontSize: '1rem',
                fontWeight: '600',
                marginBottom: '1rem',
                color: '#a5b4fc'
              }}>
                FixOps CLI Commands
              </h2>

              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {pipelineState.cliCommands.map((command) => (
                  <div key={command.purpose} style={{
                    padding: '1rem',
                    borderRadius: '8px',
                    background: 'rgba(49, 46, 129, 0.4)',
                    border: '1px solid rgba(129, 140, 248, 0.3)'
                  }}>
                    <div style={{
                      fontSize: '0.85rem',
                      fontWeight: '600',
                      color: '#c7d2fe',
                      marginBottom: '0.5rem'
                    }}>
                      {command.purpose}
                    </div>
                    <div style={{
                      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                      fontSize: '0.75rem',
                      background: 'rgba(15, 23, 42, 0.7)',
                      padding: '0.75rem',
                      borderRadius: '6px',
                      border: '1px solid rgba(129, 140, 248, 0.3)',
                      color: '#f8fafc'
                    }}>
                      {command.command}
                    </div>
                    <div style={{
                      fontSize: '0.7rem',
                      color: '#e0e7ff',
                      marginTop: '0.5rem'
                    }}>
                      {command.description}
                    </div>
                  </div>
                ))}
              </div>
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
