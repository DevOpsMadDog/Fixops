import React, { useState } from 'react'

function ScanUploadPage() {
  const [selectedFormat, setSelectedFormat] = useState('')
  const [showProcessing, setShowProcessing] = useState(false)
  
  const formats = [
    {
      type: 'sarif',
      name: 'SARIF',
      icon: '🔍',
      description: 'Static Analysis Results',
      stage: 'Code Stage',
      what_fixops_does: 'Analyzes SAST findings through Vector DB pattern matching and LLM context enrichment',
      example: 'SonarQube, CodeQL, Semgrep outputs'
    },
    {
      type: 'sbom',
      name: 'SBOM',
      icon: '📦',
      description: 'Software Bill of Materials',
      stage: 'Build Stage', 
      what_fixops_does: 'Injects dependency criticality metadata and assesses supply chain risk through consensus checking',
      example: 'CycloneDX, SPDX format SBOMs'
    },
    {
      type: 'ibom',
      name: 'IBOM',
      icon: '🏗️',
      description: 'Infrastructure Bill of Materials',
      stage: 'Deploy Stage',
      what_fixops_does: 'Validates infrastructure components against golden regression set and security policies',
      example: 'Terraform state, K8s manifests'
    },
    {
      type: 'dast',
      name: 'DAST',
      icon: '🧪', 
      description: 'Dynamic Application Security Testing',
      stage: 'Test Stage',
      what_fixops_does: 'Correlates runtime vulnerabilities with business context for exploitability assessment',
      example: 'OWASP ZAP, Burp Suite results'
    },
    {
      type: 'json',
      name: 'JSON',
      icon: '📋',
      description: 'Generic Security Data',
      stage: 'Any Stage',
      what_fixops_does: 'Processes custom security data through decision engine for context-aware analysis',
      example: 'Custom tool outputs, aggregated findings'
    }
  ]

  const processingSteps = [
    {
      step: 1,
      title: 'Data Ingestion',
      description: 'Parse and validate uploaded security data',
      icon: '📥',
      status: 'completed'
    },
    {
      step: 2, 
      title: 'Context Enrichment',
      description: 'LLM+RAG enriches findings with business context from Jira/Confluence',
      icon: '🧠',
      status: showProcessing ? 'processing' : 'pending'
    },
    {
      step: 3,
      title: 'Vector DB Lookup',
      description: 'Match against 2,847 security patterns in knowledge graph',
      icon: '🗄️',
      status: 'pending'
    },
    {
      step: 4,
      title: 'Golden Regression',
      description: 'Validate against 1,247 regression test cases',
      icon: '🏆',
      status: 'pending'
    },
    {
      step: 5,
      title: 'Policy Evaluation',
      description: 'Check compliance with OPA/Rego policies',
      icon: '📜',
      status: 'pending'
    },
    {
      step: 6,
      title: 'Consensus Decision',
      description: 'Calculate confidence score and make ALLOW/BLOCK/DEFER decision',
      icon: '⚖️',
      status: 'pending'
    }
  ]

  const handleFormatSelect = (formatType) => {
    console.log('Format selected:', formatType)
    setSelectedFormat(formatType)
    setShowProcessing(false)
  }

  const selectedFormatDetails = formats.find(f => f.type === selectedFormat)

  return (
    <div style={{
      padding: '2rem',
      maxWidth: '1600px',
      margin: '0 auto',
      backgroundColor: '#f8fafc',
      minHeight: '100vh'
    }}>
      
      {/* Header */}
      <div style={{ marginBottom: '2rem', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '2.5rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.5rem'
        }}>
          Security Data Upload & Decision Pipeline
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.125rem',
          maxWidth: '800px',
          margin: '0 auto',
          lineHeight: '1.6'
        }}>
          Upload security scan data to see how FixOps makes intelligent deployment decisions
        </p>
      </div>

      {/* Step 1: Format Selection */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        marginBottom: '2rem'
      }}>
        <h2 style={{
          fontSize: '1.5rem',
          fontWeight: '700',
          color: '#1f2937',
          marginBottom: '1.5rem'
        }}>
          Step 1: Select Your Security Data Format
        </h2>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '1.5rem'
        }}>
          {formats.map((format) => (
            <div
              key={format.type}
              onClick={() => handleFormatSelect(format.type)}
              style={{
                padding: '1.5rem',
                borderRadius: '12px',
                border: selectedFormat === format.type ? '2px solid #2563eb' : '2px solid #e5e7eb',
                backgroundColor: selectedFormat === format.type ? '#f0f9ff' : 'white',
                cursor: 'pointer',
                transition: 'all 0.2s ease-in-out'
              }}
              onMouseEnter={(e) => {
                if (selectedFormat !== format.type) {
                  e.currentTarget.style.backgroundColor = '#f9fafb'
                  e.currentTarget.style.borderColor = '#d1d5db'
                }
              }}
              onMouseLeave={(e) => {
                if (selectedFormat !== format.type) {
                  e.currentTarget.style.backgroundColor = 'white'
                  e.currentTarget.style.borderColor = '#e5e7eb'
                }
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '2rem', marginRight: '0.75rem' }}>{format.icon}</span>
                <div>
                  <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                    {format.name}
                  </h3>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                    {format.description}
                  </p>
                </div>
              </div>
              
              <div style={{ marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: '600', color: '#7c3aed' }}>
                  SSDLC Stage: {format.stage}
                </span>
              </div>
              
              <div style={{ marginBottom: '0.75rem' }}>
                <h4 style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', margin: '0 0 0.25rem 0' }}>
                  What FixOps Does:
                </h4>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0, lineHeight: '1.4' }}>
                  {format.what_fixops_does}
                </p>
              </div>
              
              <div style={{
                padding: '0.75rem',
                backgroundColor: '#f8fafc',
                borderRadius: '8px',
                border: '1px solid #e5e7eb'
              }}>
                <span style={{ fontSize: '0.75rem', fontWeight: '600', color: '#6b7280' }}>
                  Examples: {format.example}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Step 2: What Happens Next */}
      {selectedFormat && (
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          marginBottom: '2rem'
        }}>
          <h2 style={{
            fontSize: '1.5rem',
            fontWeight: '700',
            color: '#1f2937',
            marginBottom: '1.5rem'
          }}>
            Step 2: How FixOps Will Process Your {selectedFormatDetails.name} Data
          </h2>
          
          <div style={{
            backgroundColor: '#f0f9ff',
            padding: '1.5rem',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            marginBottom: '2rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
              <span style={{ fontSize: '2rem', marginRight: '1rem' }}>{selectedFormatDetails.icon}</span>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                  {selectedFormatDetails.stage} Processing
                </h3>
                <p style={{ fontSize: '1rem', color: '#6b7280', margin: 0 }}>
                  {selectedFormatDetails.what_fixops_does}
                </p>
              </div>
            </div>
          </div>
          
          {/* Processing Pipeline Visualization */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {processingSteps.map((step, idx) => (
              <div key={step.step} style={{
                display: 'flex',
                alignItems: 'center',
                padding: '1rem',
                backgroundColor: step.status === 'completed' ? '#f0fdf4' : 
                                 step.status === 'processing' ? '#fef3c7' : '#f9fafb',
                borderRadius: '12px',
                border: step.status === 'completed' ? '1px solid #bbf7d0' :
                        step.status === 'processing' ? '1px solid #fed7aa' : '1px solid #e5e7eb'
              }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: step.status === 'completed' ? '#16a34a' :
                                  step.status === 'processing' ? '#d97706' : '#9ca3af',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'white',
                  fontSize: '1.25rem',
                  marginRight: '1rem',
                  flexShrink: 0
                }}>
                  {step.status === 'processing' ? '⏳' : step.icon}
                </div>
                
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <h4 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                      {step.step}. {step.title}
                    </h4>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: '700',
                      color: step.status === 'completed' ? '#16a34a' :
                             step.status === 'processing' ? '#d97706' : '#6b7280',
                      backgroundColor: step.status === 'completed' ? '#dcfce7' :
                                      step.status === 'processing' ? '#fef3c7' : '#f3f4f6',
                      padding: '0.25rem 0.75rem',
                      borderRadius: '20px',
                      marginLeft: '1rem'
                    }}>
                      {step.status === 'completed' ? 'READY' :
                       step.status === 'processing' ? 'PROCESSING' : 'WAITING'}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                    {step.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
          
          {/* Upload Button */}
          <div style={{ textAlign: 'center', marginTop: '2rem' }}>
            <button
              onClick={() => setShowProcessing(true)}
              style={{
                padding: '1rem 2rem',
                backgroundColor: '#2563eb',
                color: 'white',
                border: 'none',
                borderRadius: '12px',
                fontSize: '1.125rem',
                fontWeight: '700',
                cursor: 'pointer',
                transition: 'background-color 0.2s ease-in-out'
              }}
            >
              🚀 Upload {selectedFormatDetails.name} & Start Decision Process
            </button>
          </div>
        </div>
      )}

      {/* Expected Output Preview */}
      {selectedFormat && (
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb'
        }}>
          <h2 style={{
            fontSize: '1.5rem',
            fontWeight: '700',
            color: '#1f2937',
            marginBottom: '1.5rem'
          }}>
            Step 3: Expected Decision Output
          </h2>
          
          <div style={{
            backgroundColor: '#f8fafc',
            padding: '1.5rem',
            borderRadius: '12px',
            border: '1px solid #e5e7eb',
            fontFamily: 'monospace',
            fontSize: '0.875rem'
          }}>
            <div style={{ color: '#16a34a', fontWeight: '700', marginBottom: '0.5rem' }}>
              ✅ DECISION: ALLOW/BLOCK/DEFER
            </div>
            <div style={{ color: '#2563eb', marginBottom: '0.5rem' }}>
              📊 Confidence Score: XX% (≥85% threshold for ALLOW)
            </div>
            <div style={{ color: '#7c3aed', marginBottom: '0.5rem' }}>
              🧠 Context: Business impact + threat intelligence assessment
            </div>
            <div style={{ color: '#d97706', marginBottom: '0.5rem' }}>
              🏆 Validation: Golden regression + policy compliance results
            </div>
            <div style={{ color: '#059669', marginBottom: '0.5rem' }}>
              🤝 Consensus: Multi-component agreement analysis
            </div>
            <div style={{ color: '#9ca3af' }}>
              🗃️ Evidence: EVD-YYYY-XXXX (immutable audit record)
            </div>
          </div>
          
          <div style={{
            marginTop: '1.5rem',
            padding: '1rem',
            backgroundColor: '#fef3c7',
            borderRadius: '8px',
            border: '1px solid #fed7aa'
          }}>
            <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#92400e', margin: '0 0 0.5rem 0' }}>
              🎯 What This Means for You:
            </h4>
            <p style={{ fontSize: '0.875rem', color: '#92400e', margin: 0, lineHeight: '1.5' }}>
              Your {selectedFormatDetails.name} data will be processed through FixOps Decision Engine to provide 
              an intelligent ALLOW/BLOCK/DEFER decision for your deployment. This replaces manual security 
              reviews with context-aware automation backed by confidence scoring.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

export default ScanUploadPage