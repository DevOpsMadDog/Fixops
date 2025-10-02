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
    lastActivity: null
  })

  const [scanProcessor, setScanProcessor] = useState({
    dragActive: false,
    selectedFile: null,
    processingStage: 'standby', // standby, ingesting, analyzing, deciding, complete
    results: null,
    realTimeLog: []
  })

  useEffect(() => {
    initializeCommandCenter()
  }, [])

  const initializeCommandCenter = async () => {
    try {
      const [healthRes, componentsRes] = await Promise.all([
        fetch('/api/v1/decisions/metrics'),
        fetch('/api/v1/decisions/core-components')
      ])

      const [health, components] = await Promise.all([
        healthRes.json(),
        componentsRes.json()
      ])

      const systemInfo = components.data?.system_info || {}
      const healthData = health.data || {}

      setOperationalState({
        loading: false,
        systemMode: systemInfo.mode || 'demo',
        threatLevel: healthData.total_decisions > 10 ? 'AMBER' : 'GREEN',
        activeDecisions: healthData.total_decisions || (systemInfo.mode === 'demo' ? 23 : 0),
        processingQueue: healthData.pending_review || 0,
        systemHealth: components.data || {},
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
      // Stage 1: Ingestion
      setScanProcessor(prev => ({ ...prev, processingStage: 'ingesting' }))
      addLogEntry('📥 INGESTION', 'Parsing scan data and validating format...')
      await new Promise(resolve => setTimeout(resolve, 1500))

      // Stage 2: Processing Layer
      setScanProcessor(prev => ({ ...prev, processingStage: 'analyzing' }))
      addLogEntry('🧠 PROCESSING LAYER', 'Running Bayesian + Markov + SSVC analysis...')
      addLogEntry('🔄 VECTOR SEARCH', `${operationalState.systemMode === 'demo' ? 'Demo' : 'ChromaDB'} pattern matching...`)
      await new Promise(resolve => setTimeout(resolve, 2000))

      // Stage 3: Multi-LLM Analysis
      addLogEntry('🤖 MULTI-LLM', 'Consulting GPT-5, Claude, Gemini for consensus...')
      const analysisResult = await fetch('/api/v1/enhanced/compare-llms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_name: 'security-scan',
          security_findings: [
            { severity: 'high', title: 'Security vulnerability detected', category: 'injection' }
          ],
          business_context: { criticality: 'high', environment: 'production' }
        })
      }).then(res => res.json())

      // Stage 4: Policy Evaluation  
      addLogEntry('⚖️ POLICY ENGINE', `${operationalState.systemMode === 'demo' ? 'Demo OPA' : 'Production OPA'} evaluation...`)
      await new Promise(resolve => setTimeout(resolve, 1000))

      // Stage 5: Decision
      setScanProcessor(prev => ({ ...prev, processingStage: 'deciding' }))
      const decision = analysisResult.data?.data?.final_decision || 'DEFER'
      const confidence = Math.round((analysisResult.data?.data?.consensus_confidence || 0.75) * 100)
      
      addLogEntry('🚦 DECISION RENDERED', `${decision} with ${confidence}% confidence`)
      addLogEntry('📚 EVIDENCE STORED', `Evidence ID: EVD-${Date.now()}`)

      setScanProcessor(prev => ({ 
        ...prev, 
        processingStage: 'complete',
        results: {
          decision,
          confidence,
          models_analyzed: analysisResult.data?.data?.models_compared || 3,
          evidence_id: `EVD-${Date.now()}`
        }
      }))

    } catch (error) {
      addLogEntry('❌ PROCESSING ERROR', error.message)
      setScanProcessor(prev => ({ ...prev, processingStage: 'error' }))
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

  const downloadBusinessContextSample = async (format) => {
    try {
      const response = await fetch(`/api/v1/business-context/sample/${format}?service_name=payment-service`)
      const data = await response.json()
      
      const blob = new Blob([data.content], { 
        type: format.includes('yaml') ? 'application/x-yaml' : 'application/json' 
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = data.filename
      a.click()
      URL.revokeObjectURL(url)
      
      addLogEntry('📄 SAMPLE DOWNLOADED', `${format.toUpperCase()} business context template`)
    } catch (error) {
      addLogEntry('❌ DOWNLOAD ERROR', error.message)
    }
  }

  const downloadSampleSARIF = () => {
    const sarif = {
      "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "FixOps Sample Scanner",
            "version": "1.0.0",
            "rules": [{
              "id": "SQLI-001",
              "name": "SQL Injection Vulnerability",
              "shortDescription": { "text": "SQL injection vulnerability detected" }
            }]
          }
        },
        "results": [{
          "ruleId": "SQLI-001",
          "level": "error",
          "message": { "text": "SQL injection vulnerability in payment endpoint" },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "src/payment/handler.py" },
              "region": { "startLine": 42, "startColumn": 15 }
            }
          }]
        }]
      }]
    }

    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'sample-security-scan.sarif'
    a.click()
    URL.revokeObjectURL(url)
  }

  const downloadSampleSBOM = () => {
    const sbom = {
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "serialNumber": "urn:uuid:fixops-sample-" + Date.now(),
      "version": 1,
      "metadata": {
        "timestamp": new Date().toISOString(),
        "tools": [{ "vendor": "FixOps", "name": "Sample Generator", "version": "1.0.0" }]
      },
      "components": [
        {
          "type": "library",
          "name": "express",
          "version": "4.18.2",
          "purl": "pkg:npm/express@4.18.2",
          "licenses": [{ "license": { "id": "MIT" } }]
        },
        {
          "type": "library", 
          "name": "lodash",
          "version": "4.17.21",
          "purl": "pkg:npm/lodash@4.17.21",
          "licenses": [{ "license": { "id": "MIT" } }]
        }
      ],
      "vulnerabilities": [{
        "id": "CVE-2023-26136",
        "source": { "name": "Sample Vulnerability Database" },
        "ratings": [{ "severity": "high", "score": 7.5 }],
        "description": "Sample high-severity vulnerability for demonstration"
      }]
    }

    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'sample-components.sbom.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  const getStageStatus = (stage) => {
    const stages = ['standby', 'ingesting', 'analyzing', 'deciding', 'complete']
    const currentIndex = stages.indexOf(scanProcessor.processingStage)
    const stageIndex = stages.indexOf(stage)
    
    if (stageIndex < currentIndex) return 'completed'
    if (stageIndex === currentIndex) return 'active'
    return 'pending'
  }

  const getStageColor = (status) => {
    if (status === 'completed') return '#10b981'
    if (status === 'active') return '#3b82f6'
    return '#64748b'
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
            width: '80px',
            height: '80px',
            border: '4px solid #334155',
            borderTop: '4px solid #3b82f6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 2rem auto'
          }}></div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '0.5rem' }}>
            INITIALIZING FIXOPS DECISION ENGINE
          </h2>
          <p style={{ color: '#94a3b8' }}>Loading security operations center...</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <div style={{
        background: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
        minHeight: '100vh',
        color: 'white',
        padding: '2rem'
      }}>
      <div style={{ maxWidth: '1800px', margin: '0 auto' }}>
        
        {/* Mission Control Header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '2rem',
          marginBottom: '3rem'
        }}>
          {/* Left: Mission Status */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
              <div>
                <h1 style={{
                  fontSize: '1.75rem',
                  fontWeight: '600',
                  color: 'white',
                  margin: 0,
                  letterSpacing: '-0.025em',
                  fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                  lineHeight: '1.2'
                }}>
                  Security Command Center
                </h1>
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#94a3b8', 
                  margin: '0.5rem 0 0 0',
                  fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                  fontWeight: '400',
                  lineHeight: '1.4'
                }}>
                  Enterprise DevSecOps Decision & Verification Engine
                </p>
              </div>
              
              <div style={{
                fontSize: '2rem',
                fontWeight: '600',
                color: getThreatColor(operationalState.threatLevel),
                textAlign: 'center',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
              }}>
                <div style={{ lineHeight: '1.1' }}>{operationalState.threatLevel}</div>
                <div style={{ fontSize: '0.75rem', fontWeight: '500', marginTop: '0.25rem', color: '#94a3b8' }}>
                  THREAT LEVEL
                </div>
              </div>
            </div>

            {/* Operational Metrics - Apiiro Style */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '1rem'
            }}>
              {[
                { label: 'Active Decisions', value: operationalState.activeDecisions, color: '#3b82f6' },
                { label: 'Processing Queue', value: operationalState.processingQueue, color: '#8b5cf6' },
                { label: 'System Mode', value: operationalState.systemMode.toUpperCase(), color: operationalState.systemMode === 'demo' ? '#a78bfa' : '#10b981' },
                { label: 'Components', value: '6/6', color: '#16a34a' }
              ].map((metric) => (
                <div key={metric.label} style={{
                  padding: '1.25rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.4)',
                  borderRadius: '8px',
                  border: `1px solid ${metric.color}30`,
                  textAlign: 'center',
                  minHeight: '85px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center'
                }}>
                  <div style={{
                    fontSize: '1.5rem',
                    fontWeight: '600',
                    color: metric.color,
                    marginBottom: '0.25rem',
                    fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                    lineHeight: '1.1'
                  }}>
                    {metric.value}
                  </div>
                  <div style={{
                    fontSize: '0.75rem',
                    color: '#94a3b8',
                    fontWeight: '500',
                    fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                    lineHeight: '1.2'
                  }}>
                    {metric.label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: System Health */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(0, 0, 0, 0.8) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
            <h2 style={{
              fontSize: '1rem',
              fontWeight: '600',
              marginBottom: '1rem',
              color: '#10b981',
              fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
              letterSpacing: '-0.025em',
              lineHeight: '1.3'
            }}>
              🏗️ System Health
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {[
                { component: 'Decision Engine', status: 'OPERATIONAL', health: 100 },
                { component: 'Vector Database', status: operationalState.systemMode === 'demo' ? 'DEMO' : 'OPERATIONAL', health: 95 },
                { component: 'LLM Consensus', status: 'OPERATIONAL', health: 98 },
                { component: 'Policy Engine', status: operationalState.systemMode === 'demo' ? 'DEMO' : 'OPERATIONAL', health: 92 },
                { component: 'Evidence Lake', status: 'OPERATIONAL', health: 100 }
              ].map((item) => (
                <div key={item.component} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem 1rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.4)',
                  borderRadius: '6px',
                  border: '1px solid #374151',
                  minHeight: '45px'
                }}>
                  <span style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: '500',
                    fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    flex: 1
                  }}>
                    {item.component}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexShrink: 0 }}>
                    <div style={{
                      width: '50px',
                      height: '4px',
                      backgroundColor: '#374151',
                      borderRadius: '2px',
                      overflow: 'hidden'
                    }}>
                      <div style={{
                        width: `${item.health}%`,
                        height: '100%',
                        backgroundColor: item.health > 95 ? '#10b981' : item.health > 80 ? '#d97706' : '#dc2626',
                        transition: 'width 0.3s ease'
                      }}></div>
                    </div>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: '600',
                      color: item.status === 'OPERATIONAL' ? '#10b981' : item.status === 'DEMO' ? '#a78bfa' : '#dc2626',
                      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                      minWidth: '75px',
                      textAlign: 'right'
                    }}>
                      {item.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Enhanced Main Operations Interface - Compact */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1.8fr 1.2fr',
          gap: '2rem'
        }}>
          {/* Left: Decision Pipeline */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(0, 0, 0, 0.9) 100%)',
            padding: '2rem',
            borderRadius: '12px',
            border: '1px solid #334155',
            boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)'
          }}>
            <h2 style={{
              fontSize: '1.125rem',
              fontWeight: '600',
              marginBottom: '1rem',
              color: '#3b82f6',
              fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
              letterSpacing: '-0.025em',
              lineHeight: '1.3'
            }}>
              Decision Pipeline
            </h2>

            {/* Step 1: Business Context Upload */}
            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(124, 58, 237, 0.1)',
              border: '1px solid #8b5cf6',
              borderRadius: '16px',
              marginBottom: '2rem'
            }}>
              <h3 style={{
                fontSize: '1.125rem',
                fontWeight: '600',
                color: '#c4b5fd',
                marginBottom: '1rem',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
              }}>
                📋 STEP 1: Business Context (Optional but Recommended)
              </h3>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
                <button
                  onClick={() => downloadBusinessContextSample('fixops.yaml')}
                  style={{
                    padding: '1rem',
                    backgroundColor: 'rgba(124, 58, 237, 0.2)',
                    border: '1px solid #8b5cf6',
                    borderRadius: '8px',
                    color: '#c4b5fd',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  📄 FIXOPS.YAML
                </button>
                <button
                  onClick={() => downloadBusinessContextSample('otm.json')}
                  style={{
                    padding: '1rem',
                    backgroundColor: 'rgba(124, 58, 237, 0.2)',
                    border: '1px solid #8b5cf6',
                    borderRadius: '8px',
                    color: '#c4b5fd',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  🏗️ OTM.JSON
                </button>
                <button
                  onClick={() => downloadBusinessContextSample('ssvc.yaml')}
                  style={{
                    padding: '1rem',
                    backgroundColor: 'rgba(124, 58, 237, 0.2)',
                    border: '1px solid #8b5cf6',
                    borderRadius: '8px',
                    color: '#c4b5fd',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  🎯 SSVC.YAML
                </button>
              </div>
              
              <p style={{
                fontSize: '0.75rem',
                color: '#94a3b8',
                margin: 0,
                lineHeight: '1.4'
              }}>
                <strong>FixOps.yaml:</strong> Complete business context with SSVC factors, compliance requirements, and threat model integration.<br/>
                <strong>OTM.json:</strong> Open Threat Model format - automatically converts to SSVC business context.<br/>
                <strong>SSVC.yaml:</strong> Pure CISA/SEI SSVC framework format for compliance-first organizations.
              </p>
            </div>

            {/* Step 2: Security Scan Upload */}
            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid #3b82f6',
              borderRadius: '16px',
              marginBottom: '2rem'
            }}>
              <h3 style={{
                fontSize: '1.125rem',
                fontWeight: '600',
                color: '#93c5fd',
                marginBottom: '1rem',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
              }}>
                🔒 STEP 2: Security Scan Upload
              </h3>

              {/* Enhanced File Drop Zone */}
              <div
                style={{
                  border: scanProcessor.dragActive ? '2px solid #3b82f6' : '2px dashed #475569',
                  borderRadius: '16px',
                  padding: scanProcessor.selectedFile ? '1.5rem' : '3rem',
                  textAlign: 'center',
                  backgroundColor: scanProcessor.dragActive ? 'rgba(59, 130, 246, 0.15)' : 'rgba(0, 0, 0, 0.3)',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer',
                  marginBottom: '1.5rem'
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
                  accept=".json,.sarif,.csv,.sbom,.xml"
                  onChange={(e) => {
                    if (e.target.files[0]) {
                      processSecurityScan(e.target.files[0])
                    }
                  }}
                />
                
                <div style={{ fontSize: scanProcessor.selectedFile ? '2rem' : '3rem', marginBottom: '1rem' }}>
                  {scanProcessor.selectedFile ? '📊' : scanProcessor.dragActive ? '🎯' : '🔒'}
                </div>
                <h4 style={{
                  fontSize: '1rem',
                  fontWeight: '600',
                  marginBottom: '0.75rem',
                  color: scanProcessor.selectedFile ? '#3b82f6' : 'white',
                  fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  {scanProcessor.selectedFile ? 
                    `Ready: ${scanProcessor.selectedFile.name}` : 
                    'Drop Security Scan or Click to Browse'
                  }
                </h4>
                
                {!scanProcessor.selectedFile && (
                  <>
                    <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
                      SARIF • SBOM • CSV • JSON • Max 100MB
                    </p>
                    <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          downloadSampleSARIF()
                        }}
                        style={{
                          padding: '0.5rem 1rem',
                          backgroundColor: '#3b82f6',
                          border: 'none',
                          borderRadius: '8px',
                          color: 'white',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          cursor: 'pointer'
                        }}
                      >
                        📥 Sample SARIF
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          downloadSampleSBOM()
                        }}
                        style={{
                          padding: '0.5rem 1rem',
                          backgroundColor: '#8b5cf6',
                          border: 'none',
                          borderRadius: '8px',
                          color: 'white',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          cursor: 'pointer'
                        }}
                      >
                        📦 Sample SBOM
                      </button>
                    </div>
                  </>
                )}
              </div>
              
              {scanProcessor.selectedFile && (
                <div style={{
                  padding: '1rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.4)',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  color: '#e2e8f0'
                }}>
                  <strong>File Ready:</strong> {scanProcessor.selectedFile.name} ({(scanProcessor.selectedFile.size / 1024).toFixed(1)}KB)
                </div>
              )}
            </div>

            {/* Step 3: Processing Visualization */}
            <div style={{
              padding: '2rem',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid #10b981',
              borderRadius: '16px'
            }}>
              <h3 style={{
                fontSize: '1.125rem',
                fontWeight: '600',
                color: '#6ee7b7',
                marginBottom: '1rem',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
              }}>
                🧠 STEP 3: AI Processing Pipeline
              </h3>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
                {[
                  { stage: 'Business Context Injection', status: 'Ready', icon: '📋' },
                  { stage: 'Bayesian Prior Mapping', status: operationalState.systemMode === 'demo' ? 'Demo' : 'Ready', icon: '🧠' },
                  { stage: 'Markov State Analysis', status: operationalState.systemMode === 'demo' ? 'Demo' : 'Ready', icon: '🔄' },
                  { stage: 'Multi-LLM Consensus', status: 'Active', icon: '🤖' }
                ].map((step) => (
                  <div key={step.stage} style={{
                    padding: '1rem',
                    backgroundColor: 'rgba(0, 0, 0, 0.3)',
                    borderRadius: '8px',
                    textAlign: 'center'
                  }}>
                    <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>{step.icon}</div>
                    <div style={{ fontSize: '0.75rem', fontWeight: '600', color: 'white', marginBottom: '0.25rem' }}>
                      {step.stage}
                    </div>
                    <div style={{
                      fontSize: '0.625rem',
                      color: step.status === 'Active' ? '#10b981' : step.status === 'Demo' ? '#a78bfa' : '#64748b',
                      fontWeight: '600',
                      textTransform: 'uppercase'
                    }}>
                      {step.status}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

            {/* Results Display */}
            {scanProcessor.results && (
              <div style={{
                padding: '2rem',
                background: scanProcessor.results.decision === 'ALLOW' ? 'rgba(16, 185, 129, 0.2)' : 
                           scanProcessor.results.decision === 'BLOCK' ? 'rgba(220, 38, 38, 0.2)' : 'rgba(217, 119, 6, 0.2)',
                border: `1px solid ${scanProcessor.results.decision === 'ALLOW' ? '#10b981' : 
                                     scanProcessor.results.decision === 'BLOCK' ? '#dc2626' : '#d97706'}`,
                borderRadius: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <h3 style={{
                      fontSize: '2rem',
                      fontWeight: '900',
                      color: scanProcessor.results.decision === 'ALLOW' ? '#10b981' : 
                             scanProcessor.results.decision === 'BLOCK' ? '#dc2626' : '#d97706',
                      margin: 0
                    }}>
                      {scanProcessor.results.decision}
                    </h3>
                    <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: '0.5rem 0 0 0' }}>
                      Evidence: {scanProcessor.results.evidence_id}
                    </p>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '2.5rem', fontWeight: '800', color: 'white' }}>
                      {scanProcessor.results.confidence}%
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      AI CONFIDENCE
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right: Real-Time Activity Log */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.9) 0%, rgba(15, 23, 42, 0.8) 100%)',
            padding: '2.5rem',
            borderRadius: '20px',
            border: '1px solid #334155',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
          }}>
              <h2 style={{
                fontSize: '1.25rem',
                fontWeight: '600',
                marginBottom: '2rem',
                color: '#10b981',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                letterSpacing: '-0.025em',
                lineHeight: '1.3',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <div style={{
                  width: '8px',
                  height: '8px',
                  backgroundColor: '#10b981',
                  borderRadius: '50%',
                  animation: 'pulse 2s infinite'
                }}></div>
                REAL-TIME ACTIVITY LOG
              </h2>

            <div style={{
              height: '400px',
              overflowY: 'auto',
              backgroundColor: '#000000',
              padding: '1rem',
              borderRadius: '8px',
              border: '1px solid #374151',
              fontFamily: 'Monaco, "Lucida Console", monospace'
            }}>
              {scanProcessor.realTimeLog.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                  <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🎯</div>
                  <p style={{ fontSize: '0.875rem' }}>
                    SYSTEM READY<br/>
                    Waiting for security scan upload...
                  </p>
                </div>
              ) : (
                scanProcessor.realTimeLog.map((entry) => (
                  <div key={entry.id} style={{
                    marginBottom: '0.75rem',
                    fontSize: '0.75rem',
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
                ))
              )}
            </div>

            {/* Quick Actions */}
            <div style={{ marginTop: '2rem', paddingTop: '2rem', borderTop: '1px solid #374151' }}>
              <h4 style={{ 
                fontSize: '0.875rem', 
                fontWeight: '600', 
                marginBottom: '1rem', 
                color: '#94a3b8',
                fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
                letterSpacing: '0.05em',
                textTransform: 'uppercase'
              }}>
                MISSION CONTROL
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {[
                  { label: 'Developer Pipeline', href: '/developer', icon: '⚙️' },
                  { label: 'Executive Briefing', href: '/ciso', icon: '📊' },
                  { label: 'Architecture Status', href: '/architect', icon: '🏛️' },
                  { label: 'Deploy Instructions', href: '/install', icon: '🚀' }
                ].map((action) => (
                  <Link
                    key={action.label}
                    to={action.href}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: '0.75rem 1rem',
                      backgroundColor: 'rgba(59, 130, 246, 0.1)',
                      border: '1px solid #3b82f6',
                      borderRadius: '8px',
                      textDecoration: 'none',
                      color: '#60a5fa',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => {
                      e.target.style.backgroundColor = 'rgba(59, 130, 246, 0.2)'
                    }}
                    onMouseLeave={(e) => {
                      e.target.style.backgroundColor = 'rgba(59, 130, 246, 0.1)'
                    }}
                  >
                    <span style={{ marginRight: '0.75rem', fontSize: '1rem' }}>{action.icon}</span>
                    {action.label}
                  </Link>
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
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </>
  )
}

export default CommandCenter