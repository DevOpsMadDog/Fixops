import React, { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import ModeToggle from './ModeToggle'

function SecurityLayout({ children }) {
  const location = useLocation()
  const [systemMetrics, setSystemMetrics] = useState({
    mode: 'demo',
    decisions_today: 0,
    avg_latency_ms: 0,
    confidence_rate: 0,
    loading: true
  })

  useEffect(() => {
    fetchSystemMetrics()
    const interval = setInterval(fetchSystemMetrics, 30000)
    return () => clearInterval(interval)
  }, [])

  const fetchSystemMetrics = async () => {
    try {
      const [metricsRes, componentsRes] = await Promise.all([
        fetch('/api/v1/decisions/metrics').catch(() => ({ json: () => ({ data: {} }) })),
        fetch('/api/v1/decisions/core-components').catch(() => ({ json: () => ({ data: { system_info: { mode: 'demo' } } }) }))
      ])

      const [metrics, components] = await Promise.all([
        metricsRes.json(),
        componentsRes.json()
      ])

      const systemInfo = components.data?.system_info || {}
      const metricsData = metrics.data || {}

      setSystemMetrics({
        mode: systemInfo.mode || 'demo',
        decisions_today: metricsData.total_decisions || (systemInfo.mode === 'demo' ? 47 : 0),
        avg_latency_ms: Math.round((metricsData.avg_decision_latency_us || 285) / 1000),
        confidence_rate: Math.round((metricsData.high_confidence_rate || 0.89) * 100),
        loading: false
      })
    } catch (error) {
      console.error('Failed to fetch system metrics:', error)
      setSystemMetrics(prev => ({ ...prev, loading: false }))
    }
  }

  const navigation = [
    {
      name: 'Command Center',
      href: '/enhanced',
      description: 'Decision Engine Operations',
      icon: '🎯',
      role: 'primary'
    },
    {
      name: 'Pipeline',
      href: '/developer',
      description: 'CI/CD Integration',
      icon: '⚙️',
      role: 'dev'
    },
    {
      name: 'Executive',
      href: '/ciso',
      description: 'Business Intelligence',
      icon: '📊',
      role: 'exec'
    },
    {
      name: 'Architecture',
      href: '/architect',
      description: 'Technical Design',
      icon: '🏛️',
      role: 'arch'
    },
    {
      name: 'Deployment',
      href: '/install',
      description: 'Enterprise Setup',
      icon: '🚀',
      role: 'ops'
    }
  ]

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#0a0e1a',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    }}>
      <header style={{
        background: 'linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 50%, #0a0e1a 100%)',
        borderBottom: '1px solid #1e293b',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.5)',
        position: 'sticky',
        top: 0,
        zIndex: 1000
      }}>
        <div style={{
          backgroundColor: '#1e293b',
          borderBottom: '1px solid #334155',
          padding: '0.5rem 0'
        }}>
          <div style={{
            maxWidth: '1800px',
            margin: '0 auto',
            padding: '0 2rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '2rem', fontSize: '0.75rem', color: '#94a3b8' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div style={{
                  width: '6px',
                  height: '6px',
                  backgroundColor: '#16a34a',
                  borderRadius: '50%',
                  animation: 'pulse 2s infinite'
                }}></div>
                SYSTEM OPERATIONAL
              </div>
              <div>DECISIONS TODAY: {systemMetrics.decisions_today}</div>
              <div>AVG LATENCY: {systemMetrics.avg_latency_ms}ms</div>
              <div>CONFIDENCE: {systemMetrics.confidence_rate}%</div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <ModeToggle />
            </div>
          </div>
        </div>

        <div style={{
          maxWidth: '1800px',
          margin: '0 auto',
          padding: '0 2rem'
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            height: '90px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{
                width: '60px',
                height: '60px',
                background: 'linear-gradient(135deg, #1e40af 0%, #7c3aed 50%, #dc2626 100%)',
                borderRadius: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '1.5rem',
                boxShadow: '0 8px 25px rgba(124, 58, 237, 0.4)',
                position: 'relative'
              }}>
                <span style={{ fontSize: '2rem', color: 'white' }}>🛡️</span>
                <div style={{
                  position: 'absolute',
                  top: '-2px',
                  right: '-2px',
                  width: '20px',
                  height: '20px',
                  backgroundColor: '#16a34a',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem'
                }}>
                  ✓
                </div>
              </div>
              <div>
                <h1 style={{
                  fontSize: '2rem',
                  fontWeight: '900',
                  color: 'white',
                  margin: 0,
                  letterSpacing: '-0.025em',
                  background: 'linear-gradient(135deg, #ffffff 0%, #60a5fa 50%, #a78bfa 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent'
                }}>
                  FixOps
                </h1>
                <p style={{
                  fontSize: '0.875rem',
                  color: '#60a5fa',
                  margin: 0,
                  fontWeight: '600',
                  letterSpacing: '0.05em'
                }}>
                  SECURE DEPLOYMENT DECISION ENGINE
                </p>
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{
                fontSize: '0.75rem',
                color: '#94a3b8',
                marginBottom: '0.25rem'
              }}>
                LAST SYNC: {new Date().toLocaleTimeString()}
              </div>
              <div style={{
                fontSize: '0.75rem',
                color: '#38bdf8',
                fontWeight: '600'
              }}>
                HOT PATH LATENCY TARGET: 299μs
              </div>
            </div>
          </div>
        </div>

        <div style={{
          maxWidth: '1800px',
          margin: '0 auto',
          padding: '0 2rem 1.5rem 2rem'
        }}>
          <nav style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
            gap: '1rem'
          }}>
            {navigation.map((item) => {
              const isActive = location.pathname === item.href

              return (
                <Link
                  key={item.name}
                  to={item.href}
                  style={{
                    textDecoration: 'none',
                    color: 'inherit'
                  }}
                >
                  <div style={{
                    padding: '1.25rem',
                    borderRadius: '12px',
                    border: `1px solid ${isActive ? 'rgba(96, 165, 250, 0.8)' : 'rgba(255, 255, 255, 0.1)'}`,
                    background: isActive
                      ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.2) 0%, rgba(56, 189, 248, 0.2) 100%)'
                      : 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%)',
                    boxShadow: isActive
                      ? '0 10px 30px rgba(37, 99, 235, 0.3)'
                      : '0 4px 20px rgba(0, 0, 0, 0.25)',
                    transition: 'all 0.3s ease'
                  }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '1rem'
                    }}>
                      <div style={{ fontSize: '1.5rem' }}>{item.icon}</div>
                      <div style={{
                        fontSize: '0.75rem',
                        color: '#38bdf8',
                        letterSpacing: '0.1em',
                        fontWeight: '600'
                      }}>
                        {item.role.toUpperCase()}
                      </div>
                    </div>
                    <h3 style={{
                      fontSize: '1.1rem',
                      fontWeight: '700',
                      color: 'white',
                      marginBottom: '0.5rem'
                    }}>
                      {item.name}
                    </h3>
                    <p style={{
                      fontSize: '0.875rem',
                      color: '#cbd5f5',
                      margin: 0
                    }}>
                      {item.description}
                    </p>
                  </div>
                </Link>
              )
            })}
          </nav>
        </div>
      </header>

      <main>
        {children}
      </main>

      <footer style={{
        marginTop: '4rem',
        padding: '2rem 0',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(2, 6, 23, 0.95))',
        borderTop: '1px solid rgba(96, 165, 250, 0.2)'
      }}>
        <div style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '0 2rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '2rem',
          color: 'white'
        }}>
          <div>
            <h4 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>FixOps Enterprise</h4>
            <p style={{ fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.6' }}>
              Automated security decision engine with deterministic processing layer,
              multi-LLM consensus, and compliance-ready evidence trails.
            </p>
          </div>

          <div>
            <h4 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>Core Capabilities</h4>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.8' }}>
              <li>• Deterministic Processing Layer</li>
              <li>• Multi-LLM Consensus Engine</li>
              <li>• Evidence Lake & Audit Trails</li>
              <li>• Policy Engine with OPA Integration</li>
            </ul>
          </div>

          <div>
            <h4 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>Deployment Modes</h4>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, fontSize: '0.875rem', color: '#94a3b8', lineHeight: '1.8' }}>
              <li>• Demo Showcase Mode</li>
              <li>• Production Hardened Mode</li>
              <li>• Hybrid Cloud Ready</li>
              <li>• Enterprise Integrations</li>
            </ul>
          </div>
        </div>
      </footer>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
      `}</style>
    </div>
  )
}

export default SecurityLayout
