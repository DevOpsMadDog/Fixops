import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

function CommandCenter() {
  const [operationalState, setOperationalState] = useState({
    loading: true,
    systemMode: 'demo',
    threatLevel: 'GREEN',
    activeDecisions: 0,
    processingQueue: 0,
    systemHealth: {},
    productionRequirements: {},
    lastActivity: null
  })

  const [scanProcessor, setScanProcessor] = useState({
    dragActive: false,
    selectedFile: null,
    processingStage: 'standby',
    results: null,
    realTimeLog: []
  })

  useEffect(() => {
    const timer = setTimeout(() => {
      setOperationalState(buildDemoOperationalState())
    }, 650)

    return () => clearTimeout(timer)
  }, [])

  const buildDemoOperationalState = () => ({
    loading: false,
    systemMode: 'demo',
    threatLevel: 'AMBER',
    activeDecisions: 23,
    processingQueue: 4,
    systemHealth: {
      core_components: ['decision_engine', 'vector_db', 'llm_rag', 'policy_engine', 'evidence_lake']
    },
    productionRequirements: {
      component_status: {
        vector_database: {
          status: 'READY',
          required: 'CHROMA_CLUSTER'
        },
        llm_consensus: {
          status: 'READY',
          required: 'EMERGENT_LLM_KEY'
        },
        policy_engine: {
          status: 'DEMO',
          required: 'OPA_SERVER'
        }
      }
    },
    lastActivity: new Date()
  })

  const handleFileDrop = async (e) => {
    e.preventDefault()
    setScanProcessor(prev => ({ ...prev, dragActive: false }))

    const files = e.dataTransfer.files
    if (files.length > 0) {
      await processSecurityScan(files[0])
    }
  }

  const processSecurityScan = async (file) => {
    setScanProcessor({
      dragActive: false,
      selectedFile: file,
      processingStage: 'ingesting',
      results: null,
      realTimeLog: []
    })

    addLogEntry('🔍 SCAN INITIATED', `Processing ${file.name} (${(file.size / 1024).toFixed(1)}KB)`)

    setTimeout(() => {
      addLogEntry('🧠 CONSENSUS', 'Multi-LLM consensus reached with 94% confidence')
      setScanProcessor(prev => ({ ...prev, processingStage: 'analyzing' }))
    }, 600)

    setTimeout(() => {
      addLogEntry('✅ ANALYSIS COMPLETE', 'Decision rendered with full evidence package')
      setScanProcessor(prev => ({ ...prev, processingStage: 'complete' }))
    }, 1200)
  }

  const addLogEntry = (action, message) => {
    setScanProcessor(prev => ({
      ...prev,
      realTimeLog: [
        ...prev.realTimeLog,
        {
          timestamp: new Date(),
          action,
          message,
          id: Date.now() + Math.random()
        }
      ]
    }))
  }

  const getThreatColor = (level) => {
    if (level === 'RED') return '#dc2626'
    if (level === 'AMBER') return '#d97706'
    return '#16a34a'
  }

  if (operationalState.loading) {
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
            width: '60px',
            height: '60px',
            border: '4px solid #334155',
            borderTop: '4px solid #3b82f6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem auto'
          }}></div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '600' }}>
            INITIALIZING FIXOPS DECISION ENGINE
          </h2>
        </div>
      </div>
    )
  }

  const isDemo = operationalState.systemMode === 'demo'

  return (
    <div style={{
      background: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
      minHeight: '100vh',
      color: 'white',
      padding: '1rem'
    }}>
      <div style={{ maxWidth: '1600px', margin: '0 auto' }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '1rem',
          marginBottom: '1rem'
        }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%)',
            padding: '1.5rem',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div>
                <h1 style={{
                  fontSize: '1.25rem',
                  fontWeight: '600',
                  color: 'white',
                  margin: 0
                }}>
                  Security Command Center
                </h1>
                <p style={{
                  fontSize: '0.75rem',
                  color: '#94a3b8',
                  margin: '0.25rem 0 0 0'
                }}>
                  Enterprise DevSecOps Decision &amp; Verification Engine
                </p>
              </div>

              <div style={{
                fontSize: '1.25rem',
                fontWeight: '600',
                color: getThreatColor(operationalState.threatLevel),
                textAlign: 'center'
              }}>
                <div>{operationalState.threatLevel}</div>
                <div style={{ fontSize: '0.625rem', fontWeight: '500', color: '#94a3b8' }}>
                  THREAT LEVEL
                </div>
              </div>
            </div>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '0.75rem'
            }}>
              {[{
                label: 'Active Decisions',
                value: operationalState.activeDecisions,
                color: '#3b82f6'
              }, {
                label: 'Processing Queue',
                value: operationalState.processingQueue,
                color: '#8b5cf6'
              }, {
                label: 'System Mode',
                value: operationalState.systemMode.toUpperCase(),
                color: operationalState.systemMode === 'demo' ? '#a78bfa' : '#10b981'
              }, {
                label: 'Components',
                value: '6/6',
                color: '#16a34a'
              }].map((metric) => (
                <div key={metric.label} style={{
                  padding: '0.75rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.4)',
                  borderRadius: '4px',
                  border: `1px solid ${metric.color}30`,
                  textAlign: 'center'
                }}>
                  <div style={{
                    fontSize: '1.125rem',
                    fontWeight: '600',
                    color: metric.color,
                    marginBottom: '0.125rem'
                  }}>
                    {metric.value}
                  </div>
                  <div style={{
                    fontSize: '0.625rem',
                    color: '#94a3b8',
                    fontWeight: '500'
                  }}>
                    {metric.label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{
            background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.6) 100%)',
            padding: '1.5rem',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{
                width: '6px',
                height: '6px',
                backgroundColor: '#10b981',
                borderRadius: '50%',
                animation: 'pulse 2s infinite',
                marginRight: '0.5rem'
              }}></div>
              <h2 style={{
                fontSize: '0.875rem',
                fontWeight: '600',
                margin: 0,
                color: '#10b981'
              }}>
                System Health
              </h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
              {[{
                component: 'Decision Engine',
                status: 'OPERATIONAL',
                health: 100,
                color: '#10b981'
              }, {
                component: 'Vector Database',
                status: 'READY',
                health: 95,
                color: '#10b981',
                required: operationalState.productionRequirements?.component_status?.vector_database?.required
              }, {
                component: 'LLM Consensus',
                status: 'READY',
                health: 98,
                color: '#10b981',
                required: operationalState.productionRequirements?.component_status?.llm_consensus?.required
              }, {
                component: 'Policy Engine',
                status: 'DEMO',
                health: 92,
                color: '#f59e0b',
                required: operationalState.productionRequirements?.component_status?.policy_engine?.required
              }, {
                component: 'Evidence Lake',
                status: 'OPERATIONAL',
                health: 100,
                color: '#10b981'
              }].map((item) => (
                <div key={item.component} style={{
                  display: 'flex',
                  alignItems: 'center',
                  padding: '0.5rem 0.75rem',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: '4px',
                  border: `1px solid ${item.color}20`
                }}>
                  <span style={{
                    fontSize: '0.75rem',
                    fontWeight: '500',
                    color: 'white',
                    flex: 1
                  }}>
                    {item.component}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <div style={{
                      width: '30px',
                      height: '2px',
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                      borderRadius: '1px',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        width: `${item.health}%`,
                        height: '100%',
                        backgroundColor: item.color,
                        borderRadius: '1px'
                      }}></div>
                    </div>
                    <div style={{ textAlign: 'right', minWidth: '80px' }}>
                      <div style={{
                        fontSize: '0.625rem',
                        fontWeight: '600',
                        color: item.color
                      }}>
                        {item.status}
                      </div>
                      {item.required && (
                        <div style={{
                          fontSize: '0.5rem',
                          color: '#dc2626',
                          fontWeight: '500'
                        }}>
                          {item.required}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={{
          background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(0, 0, 0, 0.8) 100%)',
          padding: '1.5rem',
          borderRadius: '8px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
        }}>
          <h2 style={{
            fontSize: '1rem',
            fontWeight: '600',
            marginBottom: '1rem',
            color: '#3b82f6'
          }}>
            Upload Center
          </h2>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr',
            gap: '1rem'
          }}>
            <div
              style={{
                border: scanProcessor.dragActive ? '2px solid #3b82f6' : '1px dashed #475569',
                borderRadius: '6px',
                padding: '2rem',
                textAlign: 'center',
                backgroundColor: scanProcessor.dragActive ? 'rgba(59, 130, 246, 0.1)' : 'rgba(0, 0, 0, 0.3)',
                transition: 'all 0.3s ease',
                cursor: 'pointer',
                marginBottom: '1rem'
              }}
              onDragOver={(e) => {
                e.preventDefault()
                setScanProcessor(prev => ({ ...prev, dragActive: true }))
              }}
              onDragLeave={(e) => {
                e.preventDefault()
                setScanProcessor(prev => ({ ...prev, dragActive: false }))
              }}
              onDrop={handleFileDrop}
              onClick={() => document.getElementById('scan-upload').click()}
            >
              <input
                id="scan-upload"
                type="file"
                style={{ display: 'none' }}
                accept=".json,.sarif,.csv,.sbom,.xml,.yaml,.yml"
                onChange={(e) => {
                  if (e.target.files[0]) {
                    processSecurityScan(e.target.files[0])
                  }
                }}
              />

              <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>
                {scanProcessor.selectedFile ? '📊' : '🔒'}
              </div>
              <h4 style={{
                fontSize: '1rem',
                fontWeight: '600',
                marginBottom: '0.5rem',
                color: scanProcessor.selectedFile ? '#3b82f6' : 'white'
              }}>
                {scanProcessor.selectedFile ?
                  `Ready: ${scanProcessor.selectedFile.name}` :
                  'Drop files or click to browse'}
              </h4>

              <p style={{
                fontSize: '0.875rem',
                color: '#94a3b8',
                margin: '0 0 1rem 0'
              }}>
                Security Scans: SARIF • SBOM • CSV • JSON<br />
                Business Context: FixOps.yaml • OTM.json • SSVC.yaml
              </p>

              {scanProcessor.selectedFile && (
                <div style={{
                  padding: '1rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.4)',
                  borderRadius: '6px',
                  fontSize: '0.875rem',
                  color: '#e2e8f0',
                  marginTop: '1rem'
                }}>
                  <strong>File Ready:</strong> {scanProcessor.selectedFile.name} ({(scanProcessor.selectedFile.size / 1024).toFixed(1)}KB)
                  <br />
                  <strong>Type:</strong> {scanProcessor.selectedFile.name.includes('.yaml') || scanProcessor.selectedFile.name.includes('.yml') ? 'Business Context' : 'Security Scan'}
                </div>
              )}
            </div>

            {!scanProcessor.selectedFile && (
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
                gap: '0.75rem'
              }}>
                {[
                  { label: '📊 Sample SARIF', color: '#3b82f6' },
                  { label: '📦 Sample SBOM', color: '#8b5cf6' },
                  { label: '📋 FixOps.yaml', color: '#f59e0b' },
                  { label: '🏗️ OTM.json', color: '#10b981' }
                ].map((sample) => (
                  <button
                    key={sample.label}
                    style={{
                      padding: '0.75rem',
                      backgroundColor: sample.color,
                      border: 'none',
                      borderRadius: '6px',
                      color: 'white',
                      fontSize: '0.75rem',
                      fontWeight: '500',
                      cursor: 'pointer'
                    }}
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {scanProcessor.realTimeLog.length > 0 && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.8) 0%, rgba(15, 23, 42, 0.6) 100%)',
            padding: '1rem',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            boxShadow: '0 2px 10px rgba(0, 0, 0, 0.3)'
          }}>
            <h3 style={{
              fontSize: '0.875rem',
              fontWeight: '600',
              marginBottom: '0.75rem',
              color: '#10b981'
            }}>
              Real-Time Activity Log
            </h3>
            <div style={{
              backgroundColor: '#000000',
              padding: '0.75rem',
              borderRadius: '4px',
              border: '1px solid #374151',
              fontFamily: 'Monaco, "Lucida Console", monospace',
              maxHeight: '200px',
              overflowY: 'auto'
            }}>
              {scanProcessor.realTimeLog.map((entry) => (
                <div key={entry.id} style={{
                  marginBottom: '0.25rem',
                  fontSize: '0.625rem',
                  lineHeight: '1.4'
                }}>
                  <span style={{ color: '#64748b' }}>
                    [{entry.timestamp.toLocaleTimeString()}]
                  </span>
                  <span style={{ color: '#10b981', fontWeight: '700', margin: '0 0.5rem' }}>
                    {entry.action}
                  </span>
                  <span style={{ color: '#e2e8f0' }}>
                    {entry.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{
          marginTop: '1.5rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1rem'
        }}>
          {[
            {
              title: 'API Decision Endpoint',
              description: 'Integrate FixOps decision engine directly into CI/CD pipelines.',
              link: '/install',
              action: 'View deployment guide',
              accent: '#3b82f6'
            },
            {
              title: 'Architecture Deep Dive',
              description: 'Understand how Bayesian, Markov and multi-LLM consensus combine.',
              link: '/architecture',
              action: 'Review architecture',
              accent: '#8b5cf6'
            },
            {
              title: 'Executive Summary',
              description: 'Share business and compliance readiness with leadership teams.',
              link: '/ciso',
              action: 'Open briefing center',
              accent: '#f97316'
            }
          ].map((card) => (
            <Link key={card.title} to={card.link} style={{ textDecoration: 'none' }}>
              <div style={{
                padding: '1.25rem',
                borderRadius: '10px',
                background: 'rgba(15, 23, 42, 0.7)',
                border: `1px solid ${card.accent}30`,
                boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
                height: '100%'
              }}>
                <h4 style={{
                  fontSize: '1rem',
                  marginBottom: '0.5rem',
                  color: card.accent,
                  fontWeight: '600'
                }}>
                  {card.title}
                </h4>
                <p style={{
                  fontSize: '0.85rem',
                  color: '#cbd5f5',
                  lineHeight: 1.6,
                  marginBottom: '0.75rem'
                }}>
                  {card.description}
                </p>
                <span style={{
                  fontSize: '0.75rem',
                  color: '#38bdf8',
                  fontWeight: '600'
                }}>
                  {card.action} →
                </span>
              </div>
            </Link>
          ))}
        </div>
      </div>

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}

export default CommandCenter
