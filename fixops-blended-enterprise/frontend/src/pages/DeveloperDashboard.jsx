import React, { useState, useEffect } from 'react'

function DeveloperDashboard() {
  const [selectedService, setSelectedService] = useState('payment-service v2.1.3')
  const [decisionDetails, setDecisionDetails] = useState(null)
  
  // Mock recent deployment decision for the selected service
  const serviceDecision = {
    'payment-service v2.1.3': {
      decision: 'ALLOW',
      confidence: 92,
      environment: 'Production',
      timestamp: '2 hours ago',
      evidence_id: 'EVD-2024-0847',
      decision_latency_us: 278,
      stages: {
        plan: {
          data_consumed: ['Jira Ticket #PAY-2847: Payment optimization', 'Confluence: PCI DSS Requirements'],
          fixops_analysis: 'Business impact: CRITICAL • Data sensitivity: PII + Financial',
          confidence_contribution: 0.85,
          status: 'passed'
        },
        code: {
          data_consumed: ['SonarQube SARIF: 3 medium findings', 'CodeQL SARIF: 1 low finding'],
          fixops_analysis: 'Vector DB matched similar patterns • No critical vulnerabilities detected',
          confidence_contribution: 0.94,
          status: 'passed'
        },
        build: {
          data_consumed: ['CycloneDX SBOM: 247 components', 'SLSA Provenance Level 3'],
          fixops_analysis: 'SBOM criticality assessment: 2 high-risk deps • Supply chain validated',
          confidence_contribution: 0.88,
          status: 'passed'
        },
        test: {
          data_consumed: ['OWASP ZAP DAST: Clean scan', 'Exploitability probe: Negative'],
          fixops_analysis: 'Runtime vulnerability assessment: No exploitable paths found',
          confidence_contribution: 0.96,
          status: 'passed'
        },
        release: {
          data_consumed: ['OPA/Rego Policy Check: 24 policies'],
          fixops_analysis: 'All compliance policies passed • NIST SSDF: ✅ • SOC2: ✅',
          confidence_contribution: 0.91,
          status: 'passed'
        },
        deploy: {
          data_consumed: ['Infrastructure SBOM', 'CNAPP runtime policy'],
          fixops_analysis: 'Infrastructure validation passed • Runtime controls enabled',
          confidence_contribution: 0.89,
          status: 'passed'
        },
        operate: {
          data_consumed: ['Runtime alerts: None', 'VM correlation data'],
          fixops_analysis: 'No runtime anomalies • Baseline established for monitoring',
          confidence_contribution: 0.93,
          status: 'passed'
        }
      },
      consensus_details: {
        vector_db_score: 0.94,
        golden_regression_passed: true,
        policy_violations: 0,
        criticality_factor: 1.1,
        final_consensus: 0.92
      }
    }
  }

  const currentDecision = serviceDecision[selectedService]

  return (
    <div style={{
      padding: '2rem',
      maxWidth: '1600px',
      margin: '0 auto',
      backgroundColor: '#f8fafc',
      minHeight: '100vh'
    }}>
      
      {/* Header - Developer Focus */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{
          fontSize: '2.5rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.5rem'
        }}>
          Developer Pipeline Decision
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.125rem',
          marginBottom: '1.5rem'
        }}>
          See exactly how FixOps analyzed your deployment through each SSDLC stage
        </p>
        
        {/* Service Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <label style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
            Service:
          </label>
          <select
            value={selectedService}
            onChange={(e) => setSelectedService(e.target.value)}
            style={{
              padding: '0.75rem 1rem',
              fontSize: '1rem',
              border: '2px solid #e5e7eb',
              borderRadius: '8px',
              backgroundColor: 'white'
            }}
          >
            <option value="payment-service v2.1.3">payment-service v2.1.3</option>
            <option value="user-auth v1.8.2">user-auth v1.8.2</option>
            <option value="api-gateway v3.2.1">api-gateway v3.2.1</option>
          </select>
        </div>
      </div>

      {/* Decision Summary */}
      <div style={{
        backgroundColor: currentDecision.decision === 'ALLOW' ? '#f0fdf4' : '#fef2f2',
        padding: '2rem',
        borderRadius: '16px',
        border: currentDecision.decision === 'ALLOW' ? '2px solid #16a34a' : '2px solid #dc2626',
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{
              fontSize: '2rem',
              fontWeight: 'bold',
              color: currentDecision.decision === 'ALLOW' ? '#16a34a' : '#dc2626',
              margin: '0 0 0.5rem 0'
            }}>
              DECISION: {currentDecision.decision}
            </h2>
            <p style={{ fontSize: '1.125rem', color: '#6b7280', margin: 0 }}>
              {selectedService} → {currentDecision.environment} • {currentDecision.timestamp}
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{
              fontSize: '2.5rem',
              fontWeight: 'bold',
              color: currentDecision.decision === 'ALLOW' ? '#16a34a' : '#dc2626',
              marginBottom: '0.25rem'
            }}>
              {currentDecision.confidence}%
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
              Confidence Score
            </div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
              Evidence: {currentDecision.evidence_id}
            </div>
          </div>
        </div>
      </div>

      {/* Stage-by-Stage Analysis */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        marginBottom: '2rem'
      }}>
        <h2 style={{
          fontSize: '1.75rem',
          fontWeight: '700',
          color: '#1f2937',
          marginBottom: '2rem',
          borderBottom: '2px solid #f3f4f6',
          paddingBottom: '1rem'
        }}>
          🔍 Stage-by-Stage Decision Analysis
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {Object.entries(currentDecision.stages).map(([stageName, stageData]) => (
            <div key={stageName} style={{
              padding: '1.5rem',
              backgroundColor: stageData.status === 'passed' ? '#f0fdf4' : '#fef2f2',
              borderRadius: '12px',
              border: stageData.status === 'passed' ? '1px solid #bbf7d0' : '1px solid #fecaca'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{
                  fontSize: '1.25rem',
                  fontWeight: '700',
                  color: '#1f2937',
                  margin: 0,
                  textTransform: 'capitalize'
                }}>
                  {stageName === 'plan' ? '📋' : stageName === 'code' ? '🔍' : stageName === 'build' ? '📦' : 
                   stageName === 'test' ? '🧪' : stageName === 'release' ? '🚀' : stageName === 'deploy' ? '🏗️' : '⚙️'} {stageName.toUpperCase()} Stage
                </h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <span style={{
                    fontSize: '0.875rem',
                    fontWeight: '700',
                    color: stageData.status === 'passed' ? '#16a34a' : '#dc2626',
                    backgroundColor: stageData.status === 'passed' ? '#dcfce7' : '#fecaca',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '20px'
                  }}>
                    {stageData.confidence_contribution * 100}% CONFIDENCE
                  </span>
                  <span style={{
                    fontSize: '0.75rem',
                    fontWeight: '700',
                    color: stageData.status === 'passed' ? '#16a34a' : '#dc2626'
                  }}>
                    {stageData.status === 'passed' ? '✅ PASSED' : '❌ FAILED'}
                  </span>
                </div>
              </div>
              
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <div>
                  <h4 style={{ fontSize: '1rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>
                    📥 Data Consumed
                  </h4>
                  <ul style={{ margin: 0, paddingLeft: '1rem' }}>
                    {stageData.data_consumed.map((item, idx) => (
                      <li key={idx} style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.25rem' }}>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 style={{ fontSize: '1rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>
                    🧠 FixOps Analysis
                  </h4>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0, lineHeight: '1.5' }}>
                    {stageData.fixops_analysis}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Consensus Details */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb'
      }}>
        <h2 style={{
          fontSize: '1.75rem',
          fontWeight: '700',
          color: '#1f2937',
          marginBottom: '2rem',
          borderBottom: '2px solid #f3f4f6',
          paddingBottom: '1rem'
        }}>
          🤝 Consensus & Validation Details
        </h2>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1.5rem'
        }}>
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>
              {(currentDecision.consensus_details.vector_db_score * 100).toFixed(0)}%
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
              Vector DB Score
            </div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
              Knowledge graph match
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: currentDecision.consensus_details.golden_regression_passed ? '#f0fdf4' : '#fef2f2',
            borderRadius: '12px',
            border: currentDecision.consensus_details.golden_regression_passed ? '1px solid #bbf7d0' : '1px solid #fecaca',
            textAlign: 'center'
          }}>
            <div style={{ 
              fontSize: '2rem', 
              fontWeight: 'bold', 
              color: currentDecision.consensus_details.golden_regression_passed ? '#16a34a' : '#dc2626', 
              marginBottom: '0.5rem' 
            }}>
              {currentDecision.consensus_details.golden_regression_passed ? '✅' : '❌'}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
              Golden Regression
            </div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
              1,247 test cases
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: currentDecision.consensus_details.policy_violations === 0 ? '#f0fdf4' : '#fef2f2',
            borderRadius: '12px',
            border: currentDecision.consensus_details.policy_violations === 0 ? '1px solid #bbf7d0' : '1px solid #fecaca',
            textAlign: 'center'
          }}>
            <div style={{ 
              fontSize: '2rem', 
              fontWeight: 'bold', 
              color: currentDecision.consensus_details.policy_violations === 0 ? '#16a34a' : '#dc2626', 
              marginBottom: '0.5rem' 
            }}>
              {currentDecision.consensus_details.policy_violations}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
              Policy Violations
            </div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
              24 policies checked
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>
              {currentDecision.consensus_details.criticality_factor}x
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
              Risk Multiplier
            </div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
              SBOM analysis
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DeveloperDashboard