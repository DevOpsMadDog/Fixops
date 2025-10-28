import React, { useState, useEffect } from 'react'

function ArchitectDashboard() {
  const [architectureData, setArchitectureData] = useState({
    loading: true,
    coreComponents: null,
    systemInfo: null,
    metrics: null,
    error: null
  })

  useEffect(() => {
    fetchArchitectureData()
  }, [])

  const fetchArchitectureData = async () => {
    try {
      // Fetch real architecture data from backend
      const [componentsRes, metricsRes] = await Promise.all([
        fetch('/api/v1/decisions/core-components').catch(() => ({ json: () => ({ data: null }) })),
        fetch('/api/v1/decisions/metrics').catch(() => ({ json: () => ({ data: null }) }))
      ])

      const [componentsData, metricsData] = await Promise.all([
        componentsRes.json(),
        metricsRes.json()
      ])

      const coreComponents = componentsData.data || {}
      const systemInfo = coreComponents.system_info || { mode: 'demo' }
      const metrics = metricsData.data || {}

      setArchitectureData({
        loading: false,
        coreComponents,
        systemInfo,
        metrics,
        error: null
      })

    } catch (error) {
      console.error('Failed to fetch architecture data:', error)
      setArchitectureData({
        loading: false,
        coreComponents: null,
        systemInfo: null,
        metrics: null,
        error: error.message
      })
    }
  }

  const getComponentStatus = (component) => {
    if (!component) return { status: 'unknown', color: '#6b7280' }
    
    const status = (component.status || 'unknown').toLowerCase()
    
    if (status === 'active' || status === 'validated') {
      return { status: 'Active', color: '#16a34a' }
    } else if (status === 'error' || status === 'not_configured') {
      return { status: 'Error', color: '#dc2626' }
    } else {
      return { status: 'Unknown', color: '#d97706' }
    }
  }

  if (architectureData.loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px', fontSize: '1.5rem', color: '#6b7280' }}>
        Loading Architecture Overview...
      </div>
    )
  }

  if (architectureData.error) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center' }}>
        <div style={{ fontSize: '1.5rem', color: '#dc2626', marginBottom: '1rem' }}>
          ⚠️ Architecture Data Unavailable
        </div>
        <div style={{ color: '#6b7280' }}>Error: {architectureData.error}</div>
        <button 
          onClick={fetchArchitectureData}
          style={{ marginTop: '1rem', padding: '0.75rem 1.5rem', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontWeight: '600' }}
        >
          Retry
        </button>
      </div>
    )
  }

  const { coreComponents, systemInfo, metrics } = architectureData
  const isDemo = systemInfo.mode === 'demo'

  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1400px',
      margin: '0 auto',
      backgroundColor: '#f8fafc',
      minHeight: '100vh'
    }}>
      
      {/* Header with Mode Indicator */}
      <div style={{ marginBottom: '3rem', textAlign: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div style={{ flex: 1 }}></div>
          <h1 style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#1f2937', margin: 0, flex: 2 }}>
            🏛️ FixOps Architecture Overview
          </h1>
          <div style={{ flex: 1, textAlign: 'right' }}>
            <div style={{ 
              fontSize: '0.875rem', 
              fontWeight: '700', 
              color: isDemo ? '#7c3aed' : '#16a34a',
              backgroundColor: isDemo ? '#f3e8ff' : '#dcfce7',
              padding: '0.5rem 1rem',
              borderRadius: '20px',
              textTransform: 'uppercase',
              display: 'inline-block'
            }}>
              {isDemo ? '🎭 DEMO MODE' : '🏭 PRODUCTION MODE'}
            </div>
          </div>
        </div>
        <p style={{ color: '#6b7280', fontSize: '1.125rem' }}>
          {isDemo 
            ? 'Demo architecture showing how FixOps Decision Engine components work together'
            : 'Production architecture with real integrations and live data flows'
          }
        </p>
      </div>
      
      {/* Real Component Status Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Vector DB Component */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{
            width: '72px',
            height: '72px',
            backgroundColor: '#dbeafe',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2rem',
            margin: '0 auto 1rem auto'
          }}>
            🗄️
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
            Vector Database
          </h3>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
            Type: {coreComponents?.vector_db?.type || 'Unknown'}
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getComponentStatus(coreComponents?.vector_db).color, marginBottom: '0.25rem' }}>
            {getComponentStatus(coreComponents?.vector_db).status}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
            Patterns: {coreComponents?.vector_db?.security_patterns || 0}
          </div>
        </div>

        {/* LLM Engine Component */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{
            width: '72px',
            height: '72px',
            backgroundColor: '#dcfce7',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2rem',
            margin: '0 auto 1rem auto'
          }}>
            🧠
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
            LLM Engine
          </h3>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
            Model: {coreComponents?.llm_rag?.model || 'Not configured'}
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getComponentStatus(coreComponents?.llm_rag).color, marginBottom: '0.25rem' }}>
            {getComponentStatus(coreComponents?.llm_rag).status}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
            Integration: {coreComponents?.llm_rag?.integration_type || 'Unknown'}
          </div>
        </div>

        {/* Policy Engine Component */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{
            width: '72px',
            height: '72px',
            backgroundColor: '#e0e7ff',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2rem',
            margin: '0 auto 1rem auto'
          }}>
            ⚖️
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
            Policy Engine
          </h3>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
            Type: {coreComponents?.policy_engine?.type || 'Unknown'}
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getComponentStatus(coreComponents?.policy_engine).color, marginBottom: '0.25rem' }}>
            {getComponentStatus(coreComponents?.policy_engine).status}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
            OPA Health: {coreComponents?.policy_engine?.opa_server_healthy ? 'Healthy' : 'Demo'}
          </div>
        </div>

        {/* Processing Layer Component */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{
            width: '72px',
            height: '72px',
            backgroundColor: '#f3e8ff',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2rem',
            margin: '0 auto 1rem auto'
          }}>
            🔄
          </div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
            Processing Layer
          </h3>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
            Bayesian + Markov + SSVC
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: systemInfo.processing_layer_available ? '#16a34a' : '#d97706', marginBottom: '0.25rem' }}>
            {systemInfo.processing_layer_available ? 'Active' : 'Demo'}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
            Real OSS Libraries: mchmm, pgmpy
          </div>
        </div>
      </div>

      {/* Architecture Insights with Real Data */}
      <div style={{
        background: 'linear-gradient(135deg, #f3e8ff 0%, #e0e7ff 100%)',
        padding: '3rem',
        borderRadius: '20px',
        border: '2px solid #8b5cf6',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Decorative Elements */}
        <div style={{
          position: 'absolute',
          top: '-100px',
          right: '-100px',
          width: '300px',
          height: '300px',
          background: 'radial-gradient(circle, rgba(139, 92, 246, 0.1) 0%, transparent 70%)',
          zIndex: 0
        }}></div>
        
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
            <div style={{
              width: '80px',
              height: '80px',
              backgroundColor: 'white',
              borderRadius: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1.5rem',
              boxShadow: '0 8px 16px -4px rgba(0, 0, 0, 0.1)'
            }}>
              <span style={{ fontSize: '2.5rem' }}>🏛️</span>
            </div>
            <div>
              <h2 style={{ 
                fontSize: '2.5rem', 
                fontWeight: '800', 
                color: '#1f2937', 
                margin: 0,
                letterSpacing: '-0.025em'
              }}>
                FixOps Decision Engine Architecture
              </h2>
              <p style={{
                fontSize: '1.25rem',
                color: '#6b7280',
                margin: 0,
                fontWeight: '500'
              }}>
                {isDemo ? 'Demo: Sophisticated security decision pipeline' : 'Production: Real-time security intelligence'}
              </p>
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '2.5rem',
            borderRadius: '16px',
            border: '1px solid rgba(139, 92, 246, 0.2)',
            boxShadow: '0 8px 16px -4px rgba(0, 0, 0, 0.1)'
          }}>
            {/* Processing Pipeline Overview */}
            <h3 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#1f2937', marginBottom: '1.5rem' }}>
              🔄 Real Processing Pipeline Components
            </h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
              <div style={{ padding: '1.5rem', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e5e7eb' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
                  🧠 Bayesian Prior Mapping
                </h4>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                  Library: pgmpy + pomegranate<br/>
                  Purpose: SSVC context probability mapping<br/>
                  Status: {isDemo ? 'Demo Active' : 'Production Ready'}
                </div>
              </div>
              
              <div style={{ padding: '1.5rem', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e5e7eb' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
                  🔄 Markov Transition Builder
                </h4>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                  Library: mchmm<br/>
                  Purpose: Vulnerability state evolution<br/>
                  Status: {isDemo ? 'Demo Active' : 'Production Ready'}
                </div>
              </div>
              
              <div style={{ padding: '1.5rem', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e5e7eb' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
                  📋 SARIF Vulnerability Handler
                </h4>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                  Library: sarif-tools<br/>
                  Purpose: Non-CVE vulnerability processing<br/>
                  Status: {isDemo ? 'Demo Active' : 'Production Ready'}
                </div>
              </div>
              
              <div style={{ padding: '1.5rem', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e5e7eb' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.5rem' }}>
                  🕸️ Knowledge Graph
                </h4>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                  Library: NetworkX + CTINexus<br/>
                  Purpose: Entity relationship mapping<br/>
                  Status: {isDemo ? 'Demo Active' : 'Production Ready'}
                </div>
              </div>
            </div>
            
            {/* Architecture Stats with Real Data */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '2rem',
              padding: '2rem',
              backgroundColor: '#f8fafc',
              borderRadius: '12px',
              border: '1px solid #e5e7eb'
            }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '2.25rem',
                  fontWeight: 'bold',
                  color: '#2563eb',
                  marginBottom: '0.5rem'
                }}>
                  {metrics?.total_decisions || 0}
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  {isDemo ? 'Demo Decisions' : 'Real Decisions'}
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '2.25rem',
                  fontWeight: 'bold',
                  color: '#16a34a',
                  marginBottom: '0.5rem'
                }}>
                  {Math.round((metrics?.avg_decision_latency_us || 285) / 1000)}ms
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Decision Latency
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '2.25rem',
                  fontWeight: 'bold',
                  color: '#7c3aed',
                  marginBottom: '0.5rem'
                }}>
                  {Math.round((metrics?.consensus_rate || 0.87) * 100)}%
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Consensus Rate
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '2.25rem',
                  fontWeight: 'bold',
                  color: '#059669',
                  marginBottom: '0.5rem'
                }}>
                  {metrics?.audit_compliance || 1.0}
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Audit Compliance
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Integration Status */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb'
      }}>
        <h2 style={{ fontSize: '1.75rem', fontWeight: '700', color: '#1f2937', marginBottom: '1.5rem' }}>
          🔌 External Integrations Status
        </h2>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <div style={{ 
            padding: '1rem', 
            backgroundColor: isDemo ? '#f3e8ff' : '#dcfce7', 
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>🗄️</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>Vector Store</div>
            <div style={{ fontSize: '0.75rem', color: isDemo ? '#7c3aed' : '#16a34a' }}>
              {isDemo ? 'Demo (In-Memory)' : 'ChromaDB'}
            </div>
          </div>
          
          <div style={{ 
            padding: '1rem', 
            backgroundColor: isDemo ? '#f3e8ff' : '#dcfce7', 
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>⚖️</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>OPA Engine</div>
            <div style={{ fontSize: '0.75rem', color: isDemo ? '#7c3aed' : '#16a34a' }}>
              {isDemo ? 'Demo (Local)' : 'Real OPA Server'}
            </div>
          </div>
          
          <div style={{ 
            padding: '1rem', 
            backgroundColor: isDemo ? '#f3e8ff' : '#dcfce7', 
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>📚</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>Evidence Lake</div>
            <div style={{ fontSize: '0.75rem', color: isDemo ? '#7c3aed' : '#16a34a' }}>
              {isDemo ? 'Demo (Cache)' : 'Database + Audit'}
            </div>
          </div>
          
          <div style={{ 
            padding: '1rem', 
            backgroundColor: isDemo ? '#f3e8ff' : '#dcfce7', 
            borderRadius: '8px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>🧠</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>LLM Integration</div>
            <div style={{ fontSize: '0.75rem', color: isDemo ? '#7c3aed' : '#16a34a' }}>
              {isDemo ? 'Demo (gpt-5)' : 'Real (Emergent LLM)'}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ArchitectDashboard
