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
    const timer = setTimeout(() => {
      setSystemMetrics({
        mode: 'demo',
        decisions_today: 47,
        avg_latency_ms: 0.285,
        confidence_rate: 94,
        loading: false
      })
    }, 600)

    return () => clearTimeout(timer)
  }, [])

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

        <nav style={{
          borderTop: '1px solid rgba(148, 163, 184, 0.1)',
          backgroundColor: 'rgba(10, 14, 26, 0.9)'
        }}>
          <div style={{
            maxWidth: '1800px',
            margin: '0 auto',
            padding: '0 2rem'
          }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: `repeat(${navigation.length}, minmax(0, 1fr))`,
              gap: '1rem',
              padding: '1rem 0'
            }}>
              {navigation.map((item) => {
                const isActive = location.pathname.startsWith(item.href)
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    style={{
                      textDecoration: 'none'
                    }}
                  >
                    <div style={{
                      padding: '0.75rem',
                      borderRadius: '12px',
                      border: isActive ? '1px solid rgba(96, 165, 250, 0.7)' : '1px solid rgba(148, 163, 184, 0.15)',
                      background: isActive
                        ? 'linear-gradient(135deg, rgba(59, 130, 246, 0.25) 0%, rgba(14, 116, 144, 0.15) 100%)'
                        : 'rgba(15, 23, 42, 0.6)',
                      boxShadow: isActive ? '0 10px 20px rgba(59, 130, 246, 0.2)' : 'none',
                      transition: 'all 0.3s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.4rem',
                      height: '100%'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <div style={{ fontSize: '1.25rem' }}>{item.icon}</div>
                        <div>
                          <div style={{
                            fontSize: '0.875rem',
                            fontWeight: '600',
                            color: 'white',
                            letterSpacing: '-0.01em'
                          }}>
                            {item.name}
                          </div>
                          <div style={{
                            fontSize: '0.7rem',
                            color: '#94a3b8'
                          }}>
                            {item.description}
                          </div>
                        </div>
                      </div>
                      <div style={{
                        fontSize: '0.65rem',
                        color: '#38bdf8',
                        marginTop: 'auto'
                      }}>
                        ROLE: {item.role.toUpperCase()}
                      </div>
                    </div>
                  </Link>
                )
              })}
            </div>
          </div>
        </nav>
      </header>

      <main>{children}</main>

      <footer style={{
        marginTop: '4rem',
        padding: '2rem 0',
        background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(10, 14, 26, 0.95) 100%)',
        borderTop: '1px solid rgba(148, 163, 184, 0.1)'
      }}>
        <div style={{
          maxWidth: '1400px',
          margin: '0 auto',
          padding: '0 2rem',
          display: 'flex',
          justifyContent: 'space-between',
          color: '#94a3b8',
          fontSize: '0.75rem'
        }}>
          <div>
            <div style={{ fontWeight: '600', color: '#38bdf8' }}>FixOps Decision Engine</div>
            <div>Multi-LLM consensus • Policy automation • Evidence lake</div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div>Enterprise demo experience</div>
            <div>© {new Date().getFullYear()} FixOps. All rights reserved.</div>
          </div>
        </div>
      </footer>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}

export default SecurityLayout
