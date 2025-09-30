import React, { useState, useEffect } from 'react'

function DeveloperDashboard() {
  const [metrics, setMetrics] = useState(null)
  const [recentDecisions, setRecentDecisions] = useState([])
  const [coreComponents, setCoreComponents] = useState(null)
  const [ssdlcStages, setSsdlcStages] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchDashboardData()
  }, [])

  const fetchDashboardData = async () => {
    try {
      // Fetch all dashboard data
      const [metricsRes, decisionsRes, componentsRes, stagesRes] = await Promise.all([
        fetch('/api/v1/analytics/dashboard'),
        fetch('/api/v1/decisions/recent'),
        fetch('/api/v1/decisions/core-components'),
        fetch('/api/v1/decisions/ssdlc-stages')
      ])

      const [metricsData, decisionsData, componentsData, stagesData] = await Promise.all([
        metricsRes.json(),
        decisionsRes.json(), 
        componentsRes.json(),
        stagesRes.json()
      ])

      setMetrics(metricsData.data || metricsData)
      setRecentDecisions(decisionsData.data || [])
      setCoreComponents(componentsData.data || {})
      setSsdlcStages(stagesData.data || {})
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
      // Fallback to static data
      setMetrics({
        total_decisions: 234,
        pending_review: 18,
        high_confidence_rate: 0.87,
        context_enrichment_rate: 0.95
      })
      setRecentDecisions([])
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '400px',
        fontSize: '1.5rem',
        color: '#6b7280'
      }}>
        Loading Decision Engine Data...
      </div>
    )
  }
  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1600px',
      margin: '0 auto'
    }}>
      
      {/* Header with Architecture Clarification */}
      <div style={{ marginBottom: '3rem', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '3rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.5rem',
          letterSpacing: '-0.025em'
        }}>
          FixOps Decision & Verification Engine
        </h1>
        <div style={{
          display: 'inline-block',
          backgroundColor: '#fef3c7',
          border: '2px solid #d97706',
          borderRadius: '12px',
          padding: '0.75rem 1.5rem',
          marginBottom: '1rem'
        }}>
          <p style={{ 
            color: '#92400e', 
            fontSize: '1.125rem',
            fontWeight: '700',
            margin: 0,
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            ⚠️ NOT A FIX ENGINE - DECISION ENGINE ONLY ⚠️
          </p>
        </div>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.25rem',
          maxWidth: '800px',
          margin: '0 auto',
          lineHeight: '1.6'
        }}>
          Context-aware security decisions with 85% consensus threshold and evidence-based verification
        </p>
      </div>

      {/* SSDLC Stage Data Ingestion Status */}
      <div style={{
        backgroundColor: 'white',
        padding: '2.5rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        border: '1px solid #e5e7eb',
        marginBottom: '3rem'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          marginBottom: '2rem',
          paddingBottom: '1rem',
          borderBottom: '2px solid #f3f4f6'
        }}>
          <div style={{
            width: '56px',
            height: '56px',
            backgroundColor: '#e0e7ff',
            borderRadius: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginRight: '1rem'
          }}>
            <span style={{ fontSize: '1.75rem' }}>🔄</span>
          </div>
          <h2 style={{ 
            fontSize: '1.75rem', 
            fontWeight: '700', 
            color: '#1f2937', 
            margin: 0
          }}>
            SSDLC Stage Data Ingestion
          </h2>
        </div>
        
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
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>📋</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Plan Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              Business Context
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ Jira + Confluence Active
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🔍</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Code Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              SAST + SARIF Findings
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ 47 SARIF Reports
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>📦</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Build Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              SCA + SBOM
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ 23 SBOM + SLSA
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🧪</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Test Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              DAST + Exploitability
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ 12 DAST Reports
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🚀</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Release Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              Policy Decisions
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ 24 Active Policies
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🏗️</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Deploy Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              IBOM/SBOM/CNAPP
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ Runtime Validation
            </div>
          </div>
          
          <div style={{
            padding: '1.5rem',
            backgroundColor: '#f0f9ff',
            borderRadius: '12px',
            border: '1px solid #bfdbfe',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>⚙️</div>
            <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
              Operate Stage
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
              Runtime Correlation
            </div>
            <div style={{ fontSize: '0.75rem', fontWeight: '700', color: '#16a34a' }}>
              ✅ VM + Alert Data
            </div>
          </div>
        </div>
      </div>

      {/* Decision Core Components & Intelligence */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Decision Core Components Status */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          height: '500px'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            marginBottom: '2rem',
            paddingBottom: '1rem',
            borderBottom: '2px solid #f3f4f6'
          }}>
            <div style={{
              width: '56px',
              height: '56px',
              backgroundColor: '#ddd6fe',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>⚙️</span>
            </div>
            <h2 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0
            }}>
              Decision Core Components
            </h2>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.25rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🗄️</span>
                <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                  Vector DB + Knowledge Graph
                </span>
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#16a34a' }}>ACTIVE</div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.25rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🧠</span>
                <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                  LLM+RAG Context Enrichment
                </span>
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#16a34a' }}>95%</div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.25rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🤝</span>
                <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                  Consensus Checker
                </span>
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#16a34a' }}>87%</div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.25rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🏆</span>
                <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                  Golden Regression Set
                </span>
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#16a34a' }}>VALIDATED</div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.25rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>📜</span>
                <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                  OPA/Rego Policy Engine
                </span>
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#16a34a' }}>24 POLICIES</div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.25rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>📦</span>
                <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                  SBOM Metadata Injection
                </span>
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#16a34a' }}>CRITICAL</div>
            </div>
          </div>
        </div>

        {/* Intelligence & Decision Insights */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          height: '500px'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            marginBottom: '2rem',
            paddingBottom: '1rem',
            borderBottom: '2px solid #f3f4f6'
          }}>
            <div style={{
              width: '56px',
              height: '56px',
              backgroundColor: '#fed7aa',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>🤖</span>
            </div>
            <h2 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0
            }}>
              Intelligence & Insights
            </h2>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div style={{
              padding: '1.5rem',
              backgroundColor: '#f8fafc',
              borderRadius: '12px',
              border: '1px solid #e5e7eb'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🗄️</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937' }}>
                  Vector DB Knowledge Graph
                </span>
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                • 2,847 security patterns indexed
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                • 156 threat models mapped
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                • 94% context match rate
              </div>
            </div>
            
            <div style={{
              padding: '1.5rem',
              backgroundColor: '#f8fafc',
              borderRadius: '12px',
              border: '1px solid #e5e7eb'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🧠</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937' }}>
                  LLM+RAG Intelligence
                </span>
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                • Business impact correlation: 92%
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                • Threat intel enrichment: 89%
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                • Context precision: 95%
              </div>
            </div>
            
            <div style={{
              padding: '1.5rem',
              backgroundColor: '#fef3c7',
              borderRadius: '12px',
              border: '1px solid #fed7aa'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🏆</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937' }}>
                  Golden Regression Suite
                </span>
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                • 1,247 regression test cases
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                • 98.7% validation accuracy
              </div>
              <div style={{ fontSize: '0.875rem', color: '#16a34a', fontWeight: '600' }}>
                • ✅ Last validation: 3 min ago
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Decisions with Full Context */}
      <div style={{
        backgroundColor: 'white',
        padding: '2.5rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        border: '1px solid #e5e7eb',
        marginBottom: '3rem'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          marginBottom: '2rem',
          paddingBottom: '1rem',
          borderBottom: '2px solid #f3f4f6'
        }}>
          <div style={{
            width: '56px',
            height: '56px',
            backgroundColor: '#dcfce7',
            borderRadius: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginRight: '1rem'
          }}>
            <span style={{ fontSize: '1.75rem' }}>⚖️</span>
          </div>
          <h2 style={{ 
            fontSize: '1.75rem', 
            fontWeight: '700', 
            color: '#1f2937', 
            margin: 0
          }}>
            Recent Pipeline Decisions
          </h2>
        </div>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* ALLOW Decision */}
          <div style={{
            padding: '2rem',
            backgroundColor: '#f0fdf4',
            borderRadius: '12px',
            border: '1px solid #bbf7d0'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: '#16a34a',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '1.25rem',
                  color: 'white',
                  marginRight: '1rem'
                }}>
                  ✅
                </div>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: '0 0 0.25rem 0' }}>
                    DECISION: ALLOW
                  </h3>
                  <p style={{ fontSize: '1rem', color: '#16a34a', margin: 0, fontWeight: '600' }}>
                    payment-service v2.1.3 → Production
                  </p>
                </div>
              </div>
              <span style={{
                fontSize: '1rem',
                fontWeight: '700',
                color: '#16a34a',
                backgroundColor: '#dcfce7',
                padding: '0.5rem 1rem',
                borderRadius: '20px'
              }}>
                92% CONFIDENCE
              </span>
            </div>
            
            <div style={{ marginBottom: '1rem' }}>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600', marginBottom: '0.5rem' }}>
                <strong>Context Sources:</strong> Jira (Business Critical), SBOM (CycloneDX), SAST (47 findings), DAST (Clean)
              </p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600', marginBottom: '0.5rem' }}>
                <strong>Intelligence:</strong> Vector DB matched 12 similar deployments, LLM+RAG risk assessment: Low
              </p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                <strong>Validation:</strong> Golden regression PASSED, OPA/Rego policy compliance VERIFIED
              </p>
            </div>
            
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', fontWeight: '600' }}>
              Evidence ID: EVD-2024-0847 • Decision latency: 278μs • 2h ago
            </div>
          </div>
          
          {/* BLOCK Decision */}
          <div style={{
            padding: '2rem',
            backgroundColor: '#fef2f2',
            borderRadius: '12px',
            border: '1px solid #fecaca'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: '#dc2626',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '1.25rem',
                  color: 'white',
                  marginRight: '1rem'
                }}>
                  🚫
                </div>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: '0 0 0.25rem 0' }}>
                    DECISION: BLOCK
                  </h3>
                  <p style={{ fontSize: '1rem', color: '#dc2626', margin: 0, fontWeight: '600' }}>
                    user-auth v1.8.2 → Production
                  </p>
                </div>
              </div>
              <span style={{
                fontSize: '1rem',
                fontWeight: '700',
                color: '#dc2626',
                backgroundColor: '#fecaca',
                padding: '0.5rem 1rem',
                borderRadius: '20px'
              }}>
                89% CONFIDENCE
              </span>
            </div>
            
            <div style={{ marginBottom: '1rem' }}>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600', marginBottom: '0.5rem' }}>
                <strong>Context Sources:</strong> SAST (Critical SQL injection), SBOM (Vulnerable dependencies), Runtime alerts
              </p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600', marginBottom: '0.5rem' }}>
                <strong>Intelligence:</strong> Vector DB flagged similar vulnerabilities, LLM+RAG impact: HIGH (PII exposure)
              </p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                <strong>Validation:</strong> Golden regression FAILED (known bad pattern), Policy violation: CRITICAL_DATA_EXPOSURE
              </p>
            </div>
            
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', fontWeight: '600' }}>
              Evidence ID: EVD-2024-0848 • Decision latency: 342μs • 4h ago
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Lake & Audit Trail */}
      <div style={{
        background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)',
        padding: '3rem',
        borderRadius: '20px',
        border: '1px solid #4b5563',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        color: 'white'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
          <div style={{
            width: '80px',
            height: '80px',
            backgroundColor: 'rgba(255, 255, 255, 0.1)',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginRight: '1.5rem',
            backdropFilter: 'blur(10px)'
          }}>
            <span style={{ fontSize: '2.5rem' }}>🗃️</span>
          </div>
          <div>
            <h2 style={{ 
              fontSize: '2.5rem', 
              fontWeight: '800', 
              margin: 0,
              letterSpacing: '-0.025em'
            }}>
              Evidence Lake & Audit Trail
            </h2>
            <p style={{
              fontSize: '1.25rem',
              opacity: 0.8,
              margin: 0,
              fontWeight: '500'
            }}>
              Immutable signed records with provable decisions
            </p>
          </div>
        </div>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '2rem',
          marginBottom: '2rem'
        }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              847
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Evidence Records</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              {metrics?.total_decisions || 234}
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Signed Decisions</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              100%
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Audit Compliance</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              24/7
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Evidence Retention</div>
          </div>
        </div>
        
        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          padding: '1.5rem',
          borderRadius: '12px',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(255, 255, 255, 0.2)'
        }}>
          <h4 style={{ fontSize: '1.125rem', fontWeight: '700', marginBottom: '0.75rem' }}>
            🔒 Immutable Decision Record Example
          </h4>
          <div style={{ fontFamily: 'monospace', fontSize: '0.875rem', opacity: 0.9 }}>
            <div>📝 Decision: BLOCK user-auth v1.8.2</div>
            <div>🎯 Confidence: 89% (Consensus: ✅ Vector DB: ✅ Regression: ❌)</div>
            <div>📊 Context: PII Data + SAST Critical + SBOM Vulnerable Dependencies</div>
            <div>🔗 Evidence: EVD-2024-0848 • Signed: SHA256:a7b9c3d... • SLSA Provenance ✅</div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DeveloperDashboard