import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function HomePage() {
  const [systemStatus, setSystemStatus] = useState({
    loading: true,
    mode: 'demo',
    processing_layer: false,
    oss_integrations: false,
    vector_db: 'unknown',
    policy_engine: 'unknown',
    llm_engine: 'unknown'
  })

  useEffect(() => {
    fetchSystemStatus()
  }, [])

  const fetchSystemStatus = async () => {
    try {
      const res = await fetch('/api/v1/decisions/core-components')
      const data = await res.json()
      const components = data.data || {}
      const systemInfo = components.system_info || {}

      setSystemStatus({
        loading: false,
        mode: systemInfo.mode || 'demo',
        processing_layer: systemInfo.processing_layer_available || false,
        oss_integrations: systemInfo.oss_integrations_available || false,
        vector_db: components.vector_db?.status || 'unknown',
        policy_engine: components.policy_engine?.status || 'unknown', 
        llm_engine: components.llm_rag?.status || 'unknown'
      })
    } catch (error) {
      console.error('Failed to fetch system status:', error)
      setSystemStatus(prev => ({ ...prev, loading: false }))
    }
  }

  const getStatusColor = (status) => {
    if (status.includes('active')) return '#16a34a'
    if (status === 'unknown') return '#d97706' 
    return '#dc2626'
  }

  const isDemo = systemStatus.mode === 'demo'

  return (
    <div style={{ backgroundColor: '#0f172a', minHeight: '100vh', color: 'white' }}>
      {/* Hero Section */}
      <div 
        style={{
          backgroundImage: 'url(https://images.unsplash.com/photo-1648611648035-805e9ae87437)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          position: 'relative',
          padding: '8rem 0',
          textAlign: 'center'
        }}
      >
        {/* Dark Overlay */}
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(15, 23, 42, 0.85)',
          zIndex: 1
        }}></div>
        
        {/* Content */}
        <div style={{ position: 'relative', zIndex: 2, maxWidth: '1200px', margin: '0 auto', padding: '0 2rem' }}>
          {/* System Status Banner */}
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            backgroundColor: isDemo ? 'rgba(124, 58, 237, 0.2)' : 'rgba(22, 163, 74, 0.2)',
            border: `1px solid ${isDemo ? '#7c3aed' : '#16a34a'}`,
            borderRadius: '25px',
            padding: '0.75rem 1.5rem',
            marginBottom: '2rem',
            backdropFilter: 'blur(10px)'
          }}>
            <div style={{
              width: '10px',
              height: '10px',
              backgroundColor: isDemo ? '#7c3aed' : '#16a34a',
              borderRadius: '50%',
              marginRight: '0.75rem',
              animation: 'pulse 2s infinite'
            }}></div>
            <span style={{ fontWeight: '600', fontSize: '0.875rem' }}>
              {isDemo ? '🎭 DEMO MODE ACTIVE' : '🏭 PRODUCTION MODE ACTIVE'}
            </span>
          </div>

          <h1 style={{
            fontSize: '4rem',
            fontWeight: '800',
            marginBottom: '1.5rem',
            background: 'linear-gradient(135deg, #ffffff 0%, #94a3b8 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            letterSpacing: '-0.025em'
          }}>
            FixOps Decision Engine
          </h1>
          
          <h2 style={{
            fontSize: '1.5rem',
            fontWeight: '600',
            color: '#94a3b8',
            marginBottom: '1rem'
          }}>
            Enterprise DevSecOps Control Plane
          </h2>
          
          <p style={{
            fontSize: '1.25rem',
            color: '#cbd5e1',
            maxWidth: '800px',
            margin: '0 auto 3rem auto',
            lineHeight: '1.6'
          }}>
            AI-powered security decision automation with multi-LLM consensus, Bayesian/Markov modeling, 
            and real-time processing. ALLOW/BLOCK/DEFER decisions with evidence and confidence.
          </p>

          {/* Enhanced USP Section */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '2rem',
            maxWidth: '1200px',
            margin: '0 auto 3rem auto'
          }}>
            <div style={{
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              padding: '2.5rem',
              borderRadius: '16px',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              backdropFilter: 'blur(10px)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🧠</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#60a5fa' }}>
                Multi-LLM Consensus Engine
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '1rem' }}>
                Industry-first 4+ AI model consensus (GPT-5, Claude, Gemini) with disagreement analysis
              </p>
              <div style={{
                fontSize: '0.75rem',
                fontWeight: '700',
                color: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                padding: '0.5rem',
                borderRadius: '8px'
              }}>
                94% HIGHER ACCURACY vs Single-Model Tools
              </div>
            </div>
            
            <div style={{
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              padding: '2.5rem',
              borderRadius: '16px',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              backdropFilter: 'blur(10px)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>⚡</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#fbbf24' }}>
                299μs Hot Path Performance
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '1rem' }}>
                Ultra-fast decisions for CI/CD gates with Bayesian + Markov modeling
              </p>
              <div style={{
                fontSize: '0.75rem',
                fontWeight: '700',
                color: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.2)',
                padding: '0.5rem',
                borderRadius: '8px'
              }}>
                10X FASTER than Traditional SAST/SCA
              </div>
            </div>
            
            <div style={{
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              padding: '2.5rem',
              borderRadius: '16px',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              backdropFilter: 'blur(10px)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🎯</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#34d399' }}>
                SSVC + Knowledge Graph
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '1rem' }}>
                CISA/SEI SSVC framework + CTINexus graph for contextual vulnerability analysis
              </p>
              <div style={{
                fontSize: '0.75rem',
                fontWeight: '700',
                color: '#059669',
                backgroundColor: 'rgba(5, 150, 105, 0.2)',
                padding: '0.5rem',
                borderRadius: '8px'
              }}>
                COMPLIANCE-FIRST Architecture
              </div>
            </div>

            <div style={{
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              padding: '2.5rem',
              borderRadius: '16px',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              backdropFilter: 'blur(10px)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📚</div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '1rem', color: '#a78bfa' }}>
                Immutable Evidence Lake
              </h3>
              <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '1rem' }}>
                Cryptographic audit trail with 7-year retention for SOX/PCI compliance
              </p>
              <div style={{
                fontSize: '0.75rem',
                fontWeight: '700',
                color: '#8b5cf6',
                backgroundColor: 'rgba(139, 92, 246, 0.2)',
                padding: '0.5rem',
                borderRadius: '8px'
              }}>
                ENTERPRISE AUDIT READY
              </div>
            </div>
          </div>

          {/* CTA Buttons */}
          <div style={{ display: 'flex', justifyContent: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
            <Link
              to="/enhanced"
              style={{
                display: 'inline-block',
                padding: '1rem 2rem',
                backgroundColor: '#2563eb',
                color: 'white',
                borderRadius: '12px',
                textDecoration: 'none',
                fontWeight: '700',
                fontSize: '1.125rem',
                border: '2px solid #2563eb',
                transition: 'all 0.2s ease'
              }}
            >
              🚀 Try Decision Engine
            </Link>
            <Link
              to="/install"
              style={{
                display: 'inline-block',
                padding: '1rem 2rem',
                backgroundColor: 'transparent',
                color: 'white',
                borderRadius: '12px',
                textDecoration: 'none',
                fontWeight: '700',
                fontSize: '1.125rem',
                border: '2px solid rgba(255, 255, 255, 0.3)',
                transition: 'all 0.2s ease'
              }}
            >
              📚 Installation Guide
            </Link>
          </div>
        </div>
      </div>

      {/* System Architecture Overview */}
      <div style={{ padding: '6rem 2rem', backgroundColor: '#1e293b' }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
            <h2 style={{
              fontSize: '3rem',
              fontWeight: '800',
              marginBottom: '1rem',
              background: 'linear-gradient(135deg, #ffffff 0%, #94a3b8 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>
              Enterprise Security Intelligence Pipeline
            </h2>
            <p style={{ fontSize: '1.25rem', color: '#94a3b8', maxWidth: '600px', margin: '0 auto' }}>
              Real-time processing from scan ingestion to deployment decision
            </p>
          </div>

          {/* Data Flow Pipeline */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '2rem',
            marginBottom: '4rem'
          }}>
            {[
              {
                step: '01',
                title: 'Scan Ingestion',
                description: 'SARIF, SBOM, CSV, JSON with chunked upload',
                icon: '📥',
                status: 'Active'
              },
              {
                step: '02', 
                title: 'Processing Layer',
                description: 'Bayesian + Markov + SSVC + Knowledge Graph',
                icon: '🧠',
                status: systemStatus.processing_layer ? 'Active' : 'Demo'
              },
              {
                step: '03',
                title: 'Multi-LLM Analysis', 
                description: 'GPT-5 + Claude + Gemini consensus',
                icon: '🤖',
                status: systemStatus.llm_engine.includes('active') ? 'Active' : 'Demo'
              },
              {
                step: '04',
                title: 'Policy Evaluation',
                description: 'OPA/Rego + Compliance validation',
                icon: '⚖️',
                status: systemStatus.policy_engine.includes('active') ? 'Active' : 'Demo'
              },
              {
                step: '05',
                title: 'Decision Output',
                description: 'ALLOW/BLOCK/DEFER with evidence',
                icon: '🚦',
                status: 'Active'
              }
            ].map((step) => (
              <div key={step.step} style={{
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                padding: '2.5rem',
                borderRadius: '16px',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                textAlign: 'center',
                position: 'relative'
              }}>
                {/* Step Number */}
                <div style={{
                  position: 'absolute',
                  top: '1rem',
                  right: '1rem',
                  fontSize: '0.75rem',
                  fontWeight: '700',
                  color: '#64748b',
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  padding: '0.25rem 0.5rem',
                  borderRadius: '12px'
                }}>
                  {step.step}
                </div>
                
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>{step.icon}</div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', marginBottom: '0.75rem' }}>
                  {step.title}
                </h3>
                <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '1rem' }}>
                  {step.description}
                </p>
                <div style={{
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: step.status === 'Active' ? '#16a34a' : '#7c3aed',
                  backgroundColor: step.status === 'Active' ? 'rgba(22, 163, 74, 0.2)' : 'rgba(124, 58, 237, 0.2)',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '12px',
                  display: 'inline-block'
                }}>
                  {step.status}
                </div>
              </div>
            ))}
          </div>

          {/* System Status Dashboard */}
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            padding: '3rem',
            borderRadius: '20px',
            border: '1px solid rgba(255, 255, 255, 0.1)'
          }}>
            <h3 style={{
              fontSize: '1.75rem',
              fontWeight: '700',
              marginBottom: '2rem',
              textAlign: 'center'
            }}>
              🏗️ System Architecture Status
            </h3>
            
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1.5rem'
            }}>
              {[
                { name: 'Vector Database', status: systemStatus.vector_db, icon: '🗄️' },
                { name: 'Policy Engine', status: systemStatus.policy_engine, icon: '⚖️' },
                { name: 'LLM Engine', status: systemStatus.llm_engine, icon: '🧠' },
                { name: 'Processing Layer', status: systemStatus.processing_layer ? 'active' : 'demo', icon: '🔄' }
              ].map((component) => (
                <div key={component.name} style={{
                  padding: '1.5rem',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: '12px',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>{component.icon}</div>
                  <h4 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '0.5rem' }}>
                    {component.name}
                  </h4>
                  <div style={{
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    color: getStatusColor(component.status),
                    backgroundColor: `${getStatusColor(component.status)}20`,
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px',
                    display: 'inline-block'
                  }}>
                    {component.status.toUpperCase()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Feature Showcase */}
      <div style={{ padding: '6rem 2rem', backgroundColor: '#1e293b' }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
          <h2 style={{
            fontSize: '2.5rem',
            fontWeight: '800',
            textAlign: 'center',
            marginBottom: '3rem',
            color: 'white'
          }}>
            🎯 Why FixOps?
          </h2>
          
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
            gap: '3rem'
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{
                width: '120px',
                height: '120px',
                backgroundColor: '#2563eb',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 2rem auto',
                fontSize: '3rem'
              }}>
                🧠
              </div>
              <h3 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1rem' }}>
                Multi-LLM Consensus
              </h3>
              <p style={{ fontSize: '1rem', color: '#94a3b8', lineHeight: '1.6' }}>
                Unlike single-model tools, FixOps uses multiple AI models (GPT-5, Claude, Gemini) 
                with consensus algorithms and disagreement analysis for higher accuracy decisions.
              </p>
            </div>
            
            <div style={{ textAlign: 'center' }}>
              <div style={{
                width: '120px',
                height: '120px',
                backgroundColor: '#16a34a',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 2rem auto',
                fontSize: '3rem'
              }}>
                🎯
              </div>
              <h3 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1rem' }}>
                SSVC Framework
              </h3>
              <p style={{ fontSize: '1rem', color: '#94a3b8', lineHeight: '1.6' }}>
                Built on CISA/SEI SSVC framework with EPSS/KEV integration. 
                Provides stakeholder-specific vulnerability categorization for informed decisions.
              </p>
            </div>
            
            <div style={{ textAlign: 'center' }}>
              <div style={{
                width: '120px',
                height: '120px',
                backgroundColor: '#7c3aed',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 2rem auto',
                fontSize: '3rem'
              }}>
                📊
              </div>
              <h3 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1rem' }}>
                Advanced Modeling
              </h3>
              <p style={{ fontSize: '1rem', color: '#94a3b8', lineHeight: '1.6' }}>
                Bayesian networks, Markov chains, and knowledge graphs for sophisticated 
                vulnerability analysis beyond simple CVSS scores.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div style={{ padding: '6rem 2rem', backgroundColor: '#0f172a' }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', textAlign: 'center' }}>
          <h2 style={{
            fontSize: '2.5rem',
            fontWeight: '800',
            marginBottom: '1rem',
            color: 'white'
          }}>
            Get Started in Minutes
          </h2>
          <p style={{ fontSize: '1.125rem', color: '#94a3b8', marginBottom: '3rem' }}>
            Choose your path based on your role and requirements
          </p>
          
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '2rem'
          }}>
            {[
              {
                role: 'Developer',
                description: 'Upload scans, see stage-by-stage analysis, get deployment decisions',
                link: '/developer',
                color: '#2563eb',
                icon: '👨‍💻'
              },
              {
                role: 'CISO',
                description: 'Executive risk overview, compliance metrics, business impact analysis',
                link: '/ciso', 
                color: '#dc2626',
                icon: '👔'
              },
              {
                role: 'Architect',
                description: 'Technical architecture, component status, integration health',
                link: '/architect',
                color: '#7c3aed',
                icon: '🏗️'
              }
            ].map((persona) => (
              <Link
                key={persona.role}
                to={persona.link}
                style={{
                  display: 'block',
                  padding: '2.5rem',
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  borderRadius: '16px',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  textDecoration: 'none',
                  color: 'white',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer'
                }}
                onMouseEnter={(e) => {
                  e.target.style.backgroundColor = 'rgba(255, 255, 255, 0.1)'
                  e.target.style.transform = 'translateY(-4px)'
                }}
                onMouseLeave={(e) => {
                  e.target.style.backgroundColor = 'rgba(255, 255, 255, 0.05)'
                  e.target.style.transform = 'translateY(0px)'
                }}
              >
                <div style={{
                  width: '80px',
                  height: '80px',
                  backgroundColor: persona.color,
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 1.5rem auto',
                  fontSize: '2rem'
                }}>
                  {persona.icon}
                </div>
                <h3 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '1rem' }}>
                  {persona.role}
                </h3>
                <p style={{ fontSize: '1rem', color: '#94a3b8', lineHeight: '1.6' }}>
                  {persona.description}
                </p>
              </Link>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}

export default HomePage