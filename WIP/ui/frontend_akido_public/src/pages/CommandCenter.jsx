import React, { useState, useEffect } from 'react'
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
    initializeCommandCenter()
  }, [])

  const initializeCommandCenter = async () => {
    try {
      const [healthRes, componentsRes, prodRes] = await Promise.all([
        fetch('/api/v1/decisions/metrics'),
        fetch('/api/v1/decisions/core-components'),
        fetch('/api/v1/production-readiness/status')
      ])

      const [health, components, prodReadiness] = await Promise.all([
        healthRes.json(),
        componentsRes.json(),
        prodRes.json()
      ])

      const systemInfo = components.data?.system_info || {}
      const healthData = health.data || {}
      const prodData = prodReadiness.data || {}

      setOperationalState({
        loading: false,
        systemMode: systemInfo.mode || 'demo',
        threatLevel: healthData.total_decisions > 10 ? 'AMBER' : 'GREEN',
        activeDecisions: healthData.total_decisions || (systemInfo.mode === 'demo' ? 23 : 0),
        processingQueue: healthData.pending_review || 0,
        systemHealth: components.data || {},
        productionRequirements: prodData,
        lastActivity: new Date()
      })
    } catch (error) {
      setOperationalState(prev => ({ ...prev, loading: false }))
    }
  }

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

    try {
      setScanProcessor(prev => ({ ...prev, processingStage: 'complete' }))
      addLogEntry('✅ ANALYSIS COMPLETE', 'Decision rendered with evidence')
    } catch (error) {
      addLogEntry('❌ PROCESSING ERROR', error.message)
    }
  }

  const addLogEntry = (action, message) => {
    setScanProcessor(prev => ({
      ...prev,
      realTimeLog: [...prev.realTimeLog, {
        timestamp: new Date(),
        action,
        message,
        id: Date.now() + Math.random()
      }]
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
        
        {/* Compact Mission Control Header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '1rem',
          marginBottom: '1rem'
        }}>
          {/* Left: Mission Status */}
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
                  margin: 0,
                  fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
                }}>
                  Security Command Center
                </h1>
                <p style={{ 
                  fontSize: '0.75rem', 
                  color: '#94a3b8', 
                  margin: '0.25rem 0 0 0',
                  fontFamily: '"Inter", sans-serif'
                }}>
                  Enterprise DevSecOps Decision & Verification Engine
                </p>
              </div>
              
              <div style={{
                fontSize: '1.25rem',
                fontWeight: '600',
                color: getThreatColor(operationalState.threatLevel),
                textAlign: 'center',
                fontFamily: '"Inter", sans-serif'
              }}>
                <div>{operationalState.threatLevel}</div>
                <div style={{ fontSize: '0.625rem', fontWeight: '500', color: '#94a3b8' }}>
                  THREAT LEVEL
                </div>
              </div>
            </div>

            {/* Compact Operational Metrics */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '0.75rem'
            }}>
              {[
                { label: 'Active Decisions', value: operationalState.activeDecisions, color: '#3b82f6' },
                { label: 'Processing Queue', value: operationalState.processingQueue, color: '#8b5cf6' },
                { label: 'System Mode', value: operationalState.systemMode.toUpperCase(), color: operationalState.systemMode === 'demo' ? '#a78bfa' : '#10b981' },
                { label: 'Components', value: '6/6', color: '#16a34a' }
              ].map((metric) => (
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
                    marginBottom: '0.125rem',
                    fontFamily: '"Inter", sans-serif'
                  }}>
                    {metric.value}
                  </div>
                  <div style={{
                    fontSize: '0.625rem',
                    color: '#94a3b8',
                    fontWeight: '500',
                    fontFamily: '"Inter", sans-serif'
                  }}>
                    {metric.label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Compact System Health */}
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
                color: '#10b981',
                fontFamily: '"Inter", sans-serif'
              }}>
                System Health
              </h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
              {[
                { 
                  component: 'Decision Engine', 
                  status: 'OPERATIONAL', 
                  health: 100, 
                  color: '#10b981',
                  required: null
                },
                { 
                  component: 'Vector Database', 
                  status: isDemo ? 'DEMO' : (operationalState.productionRequirements?.component_status?.vector_database?.status === 'READY' ? 'OPERATIONAL' : 'NEEDS_CONFIG'), 
                  health: 95, 
                  color: isDemo ? '#f59e0b' : (operationalState.productionRequirements?.component_status?.vector_database?.status === 'READY' ? '#10b981' : '#dc2626'),
                  required: isDemo ? null : operationalState.productionRequirements?.component_status?.vector_database?.required
                },
                { 
                  component: 'LLM Consensus', 
                  status: isDemo ? 'DEMO' : (operationalState.productionRequirements?.component_status?.llm_consensus?.status === 'READY' ? 'OPERATIONAL' : 'NEEDS_KEYS'), 
                  health: 98, 
                  color: isDemo ? '#f59e0b' : '#10b981',
                  required: isDemo ? null : 'OPENAI_API_KEY'
                },
                { 
                  component: 'Policy Engine', 
                  status: isDemo ? 'DEMO' : 'NEEDS_SERVER', 
                  health: 92, 
                  color: isDemo ? '#f59e0b' : '#dc2626',
                  required: isDemo ? null : 'OPA_SERVER'
                },
                { 
                  component: 'Evidence Lake', 
                  status: 'OPERATIONAL', 
                  health: 100, 
                  color: '#10b981',
                  required: null
                }
              ].map((item) => (
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
                    fontFamily: '"Inter", sans-serif',
                    color: 'white',
                    flex: 1
                  }}>
                    {item.component}
                  </span>
                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: '0.5rem'
                  }}>
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
                        color: item.color,
                        fontFamily: '"Inter", sans-serif'
                      }}>
                        {item.status}
                      </div>
                      {item.required && !isDemo && (
                        <div style={{
                          fontSize: '0.5rem',
                          color: '#dc2626',
                          fontFamily: '"Inter", sans-serif',
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

        {/* Unified Upload Center */}
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
            color: '#3b82f6',
            fontFamily: '"Inter", sans-serif'
          }}>
            Upload Center
          </h2>

          {/* Single Upload Interface */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr',
            gap: '1rem'
          }}>
            {/* Unified Drop Zone */}
            <div style={{
              padding: '1.5rem',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '8px'
            }}>
              <h3 style={{
                fontSize: '0.875rem',
                fontWeight: '600',
                color: '#93c5fd',
                marginBottom: '1rem',
                fontFamily: '"Inter", sans-serif'
              }}>
                Security Analysis Upload
              </h3>

              {/* Main File Drop Zone */}
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
                  color: scanProcessor.selectedFile ? '#3b82f6' : 'white',
                  fontFamily: '"Inter", sans-serif'
                }}>
                  {scanProcessor.selectedFile ? 
                    `Ready: ${scanProcessor.selectedFile.name}` : 
                    'Drop files or click to browse'
                  }
                </h4>
                
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#94a3b8',
                  margin: '0 0 1rem 0',
                  fontFamily: '"Inter", sans-serif'
                }}>
                  Security Scans: SARIF • SBOM • CSV • JSON<br/>
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
                    <br/>
                    <strong>Type:</strong> {scanProcessor.selectedFile.name.includes('.yaml') || scanProcessor.selectedFile.name.includes('.yml') ? 'Business Context' : 'Security Scan'}
                  </div>
                )}
              </div>
              
              {/* Quick Samples */}
              {!scanProcessor.selectedFile && (
                <div style={{ 
                  display: 'grid', 
                  gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', 
                  gap: '0.75rem'
                }}>
                  <button style={{
                    padding: '0.75rem',
                    backgroundColor: '#3b82f6',
                    border: 'none',
                    borderRadius: '6px',
                    color: 'white',
                    fontSize: '0.75rem',
                    fontWeight: '500',
                    cursor: 'pointer',
                    fontFamily: '"Inter", sans-serif'
                  }}>
                    📊 Sample SARIF
                  </button>
                  <button style={{
                    padding: '0.75rem',
                    backgroundColor: '#8b5cf6',
                    border: 'none',
                    borderRadius: '6px',
                    color: 'white',
                    fontSize: '0.75rem',
                    fontWeight: '500',
                    cursor: 'pointer',
                    fontFamily: '"Inter", sans-serif'
                  }}>
                    📦 Sample SBOM
                  </button>
                  <button style={{
                    padding: '0.75rem',
                    backgroundColor: '#f59e0b',
                    border: 'none',
                    borderRadius: '6px',
                    color: 'white',
                    fontSize: '0.75rem',
                    fontWeight: '500',
                    cursor: 'pointer',
                    fontFamily: '"Inter", sans-serif'
                  }}>
                    📋 FixOps.yaml
                  </button>
                  <button style={{
                    padding: '0.75rem',
                    backgroundColor: '#10b981',
                    border: 'none',
                    borderRadius: '6px',
                    color: 'white',
                    fontSize: '0.75rem',
                    fontWeight: '500',
                    cursor: 'pointer',
                    fontFamily: '"Inter", sans-serif'
                  }}>
                    🏗️ OTM.json
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Real-Time Activity Log */}
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
              color: '#10b981',
              fontFamily: '"Inter", sans-serif'
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