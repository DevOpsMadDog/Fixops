import React, { useEffect, useState } from 'react'

function ArchitectureCenter() {
  const [architectureState, setArchitectureState] = useState({
    loading: true,
    systemMode: 'demo',
    coreComponents: {},
    dataFlow: [],
    performanceMetrics: {},
    integrationMap: {}
  })

  useEffect(() => {
    const timer = setTimeout(() => {
      const systemInfo = { mode: 'demo' }
      const coreComponents = {
        vector_db: { status: 'ready', security_patterns: 1248 },
        llm_rag: { status: 'ready', model: 'Emergent-Multi-LLM' },
        policy_engine: { status: 'demo', policies_loaded: ['Deployment', 'Secrets', 'Runtime'] }
      }
      const metrics = { avg_decision_latency_us: 278, consensus_rate: 0.94 }

      setArchitectureState({
        loading: false,
        systemMode: 'demo',
        coreComponents,
        dataFlow: generateDataFlow(systemInfo),
        performanceMetrics: generatePerformanceMetrics(metrics, systemInfo),
        integrationMap: generateIntegrationMap(coreComponents, systemInfo)
      })
    }, 600)

    return () => clearTimeout(timer)
  }, [])

  const generateDataFlow = (systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'

    return [
      {
        stage: 'Input Layer',
        component: 'Scan Ingestion',
        technology: 'SARIF + SBOM + CSV Parser',
        status: 'ACTIVE',
        throughput: isDemo ? '1.2K scans/day' : '0 scans (ready)',
        latency: '< 100ms'
      },
      {
        stage: 'Processing Layer',
        component: 'Bayesian Prior Mapping',
        technology: 'pgmpy + pomegranate',
        status: isDemo ? 'ACTIVE' : 'READY',
        throughput: isDemo ? '500 decisions/hour' : 'Standby',
        latency: '< 50μs'
      },
      {
        stage: 'Processing Layer',
        component: 'Markov Transition Matrix',
        technology: 'mchmm library',
        status: isDemo ? 'ACTIVE' : 'READY',
        throughput: isDemo ? 'Real-time' : 'Standby',
        latency: '< 75μs'
      },
      {
        stage: 'Intelligence Layer',
        component: 'Vector Database',
        technology: isDemo ? 'Demo Store' : 'ChromaDB + Sentence Transformers',
        status: 'ACTIVE',
        throughput: isDemo ? '10K patterns' : '5 patterns',
        latency: '< 150μs'
      },
      {
        stage: 'Intelligence Layer',
        component: 'Multi-LLM Consensus',
        technology: 'GPT-5 + Claude + Gemini',
        status: 'ACTIVE',
        throughput: isDemo ? '3 models' : '1 model (Emergent)',
        latency: '< 2s'
      },
      {
        stage: 'Decision Layer',
        component: 'Policy Engine',
        technology: isDemo ? 'Demo OPA' : 'Production OPA + rego',
        status: 'ACTIVE',
        throughput: isDemo ? '24 policies' : '2 policies',
        latency: '< 25μs'
      },
      {
        stage: 'Output Layer',
        component: 'Evidence Lake',
        technology: isDemo ? 'Demo Cache' : 'PostgreSQL + Audit',
        status: 'ACTIVE',
        throughput: 'Immutable storage',
        latency: '< 10ms'
      }
    ]
  }

  const generatePerformanceMetrics = (data, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'

    return {
      hotPathLatency: isDemo ? '278μs' : `${data.avg_decision_latency_us || 285}μs`,
      throughput: isDemo ? '2.4K decisions/hour' : '0 decisions/hour',
      availability: '99.9%',
      consensusRate: isDemo ? '94%' : `${Math.round((data.consensus_rate || 0.87) * 100)}%`,
      errorRate: '< 0.1%',
      cacheHitRate: '87%'
    }
  }

  const generateIntegrationMap = (components, systemInfo) => {
    const isDemo = systemInfo.mode === 'demo'

    return {
      vectorStore: {
        technology: isDemo ? 'In-Memory Demo Store' : 'ChromaDB + Sentence Transformers',
        status: components.vector_db?.status || 'unknown',
        capacity: isDemo ? '10K patterns' : `${components.vector_db?.security_patterns || 0} patterns`
      },
      llmEngine: {
        technology: isDemo ? 'Demo Multi-LLM' : 'Emergent LLM Integration',
        status: components.llm_rag?.status || 'unknown',
        models: isDemo ? 'GPT-5, Claude, Gemini' : components.llm_rag?.model || 'Not configured'
      },
      policyEngine: {
        technology: isDemo ? 'Demo OPA Engine' : 'Production OPA Server',
        status: components.policy_engine?.status || 'unknown',
        policies: isDemo ? '24 security policies' : `${components.policy_engine?.policies_loaded?.length || 0} policies`
      },
      evidenceLake: {
        technology: isDemo ? 'Demo Cache Storage' : 'Production Database + Audit',
        status: 'active',
        retention: '7 years compliance'
      }
    }
  }

  if (architectureState.loading) {
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
            borderTop: '4px solid #3b82f6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 2rem auto'
          }}></div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '0.5rem' }}>
            LOADING ARCHITECTURE INTELLIGENCE
          </h2>
          <p style={{ color: '#94a3b8' }}>Analyzing system components...</p>
        </div>
      </div>
    )
  }

  const isDemo = architectureState.systemMode === 'demo'

  return (
    <div style={{
      background: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '1rem'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto' }}>
        <div style={{
          background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2) 0%, rgba(30, 41, 59, 0.6) 100%)',
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
                Architecture Intelligence Center
              </h1>
              <p style={{ fontSize: '0.85rem', color: '#bfdbfe', margin: '0.25rem 0 0 0' }}>
                Bayesian reasoning, Markov transitions, and multi-LLM consensus pipeline
              </p>
            </div>

            <div style={{
              textAlign: 'right',
              fontSize: '0.75rem',
              color: '#bfdbfe'
            }}>
              <div>Hot Path Latency: {architectureState.performanceMetrics.hotPathLatency}</div>
              <div>Consensus Rate: {architectureState.performanceMetrics.consensusRate}</div>
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
            border: '1px solid rgba(96, 165, 250, 0.25)',
            padding: '1.5rem'
          }}>
            <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem', color: '#60a5fa' }}>
              End-to-End Data Flow
            </h2>

            <div style={{ display: 'grid', gap: '1rem' }}>
              {architectureState.dataFlow.map((stage) => (
                <div key={stage.component} style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  background: 'rgba(30, 41, 59, 0.7)',
                  border: '1px solid rgba(37, 99, 235, 0.3)'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <div>
                      <div style={{ fontSize: '0.75rem', color: '#bfdbfe', letterSpacing: '0.08em' }}>{stage.stage.toUpperCase()}</div>
                      <h3 style={{ fontSize: '1rem', margin: 0, color: '#e0f2fe' }}>{stage.component}</h3>
                      <p style={{ fontSize: '0.75rem', color: '#cbd5f5', margin: '0.25rem 0 0 0' }}>{stage.technology}</p>
                    </div>
                    <div style={{
                      padding: '0.25rem 0.75rem',
                      borderRadius: '9999px',
                      background: 'rgba(37, 99, 235, 0.2)',
                      border: '1px solid rgba(59, 130, 246, 0.4)',
                      fontSize: '0.7rem',
                      color: '#60a5fa',
                      fontWeight: '600'
                    }}>
                      {stage.status}
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#bae6fd', fontSize: '0.75rem' }}>
                    <span>Throughput: {stage.throughput}</span>
                    <span>Latency: {stage.latency}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gap: '1rem' }}>
            <div style={{
              background: 'rgba(15, 23, 42, 0.8)',
              borderRadius: '10px',
              border: '1px solid rgba(45, 212, 191, 0.25)',
              padding: '1.5rem'
            }}>
              <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem', color: '#5eead4' }}>
                Performance Envelope
              </h2>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {Object.entries(architectureState.performanceMetrics).map(([metric, value]) => (
                  <div key={metric} style={{ display: 'flex', justifyContent: 'space-between', color: '#ccfbf1' }}>
                    <span style={{ fontSize: '0.8rem' }}>{metric.replace(/([A-Z])/g, ' $1')}</span>
                    <span style={{ fontWeight: '600' }}>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{
              background: 'rgba(15, 23, 42, 0.8)',
              borderRadius: '10px',
              border: '1px solid rgba(129, 140, 248, 0.25)',
              padding: '1.5rem'
            }}>
              <h2 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '1rem', color: '#a5b4fc' }}>
                Integration Map
              </h2>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {Object.entries(architectureState.integrationMap).map(([component, details]) => (
                  <div key={component} style={{
                    padding: '0.85rem',
                    borderRadius: '8px',
                    background: 'rgba(30, 41, 59, 0.7)',
                    border: '1px solid rgba(129, 140, 248, 0.3)'
                  }}>
                    <div style={{ fontSize: '0.8rem', color: '#c7d2fe', marginBottom: '0.5rem' }}>{component.toUpperCase()}</div>
                    <div style={{ fontSize: '0.75rem', color: '#ede9fe', lineHeight: 1.6 }}>
                      <div><strong>Technology:</strong> {details.technology}</div>
                      <div><strong>Status:</strong> {details.status}</div>
                      {details.capacity && <div><strong>Capacity:</strong> {details.capacity}</div>}
                      {details.models && <div><strong>Models:</strong> {details.models}</div>}
                      {details.policies && <div><strong>Policies:</strong> {details.policies}</div>}
                      {details.retention && <div><strong>Retention:</strong> {details.retention}</div>}
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

export default ArchitectureCenter
