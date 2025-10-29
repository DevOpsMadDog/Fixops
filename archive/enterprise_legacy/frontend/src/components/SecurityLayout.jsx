import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import ModeToggle from './ModeToggle'

function Layout({ children }) {
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
    const interval = setInterval(fetchSystemMetrics, 30000) // Update every 30s
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

  const isDemo = systemMetrics.mode === 'demo'

  return (
    <div style={{ 
      minHeight: '100vh', 
      backgroundColor: '#0a0e1a',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
    }}>
      {/* Security Operations Center Header */}
      <header style={{
        background: 'linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 50%, #0a0e1a 100%)',
        borderBottom: '1px solid #1e293b',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.5)',
        position: 'sticky',
        top: 0,
        zIndex: 1000
      }}>
        {/* Top Status Bar */}
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

        {/* Main Header */}
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
            {/* Brand Identity */}
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
                  ENTERPRISE DECISION ENGINE
                </p>
              </div>
            </div>

            {/* Mission Critical Stats */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '3rem' }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: '800', color: '#10b981' }}>
                  99.9%
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: '600' }}>
                  UPTIME SLA
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: '800', color: '#3b82f6' }}>
                  &lt;300μs
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: '600' }}>
                  HOT PATH
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: '800', color: '#8b5cf6' }}>
                  4+
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: '600' }}>
                  AI MODELS
                </div>
              </div>
            </div>
          </div>

          {/* Security Operations Navigation */}
          <div style={{
            borderTop: '1px solid #334155',
            paddingTop: '0'
          }}>
            <nav style={{
              display: 'flex',
              gap: '0',
              overflowX: 'auto'
            }}>
              {navigation.map((item) => {
                const isActive = location.pathname === item.href
                const roleColors = {
                  primary: '#dc2626',
                  dev: '#059669', 
                  exec: '#7c3aed',
                  arch: '#2563eb',
                  ops: '#d97706'
                }
                const roleColor = roleColors[item.role] || '#64748b'
                
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      padding: '1rem 1.5rem',
                      textDecoration: 'none',
                      borderBottom: isActive ? `3px solid ${roleColor}` : '3px solid transparent',
                      backgroundColor: isActive ? `${roleColor}15` : 'transparent',
                      color: isActive ? roleColor : '#94a3b8',
                      transition: 'all 0.2s ease-in-out',
                      borderTop: isActive ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid transparent',
                      borderLeft: isActive ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid transparent',
                      borderRight: isActive ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid transparent',
                      borderTopLeftRadius: isActive ? '8px' : '0',
                      borderTopRightRadius: isActive ? '8px' : '0',
                      minWidth: '120px'
                    }}
                  >
                    <div style={{ 
                      fontSize: '1.5rem', 
                      marginBottom: '0.25rem',
                      filter: isActive ? 'none' : 'grayscale(50%)'
                    }}>
                      {item.icon}
                    </div>
                    <div style={{ 
                      fontSize: '0.875rem', 
                      fontWeight: '700',
                      textAlign: 'center',
                      marginBottom: '0.125rem'
                    }}>
                      {item.name}
                    </div>
                    <div style={{ 
                      fontSize: '0.625rem', 
                      color: '#64748b',
                      textAlign: 'center',
                      fontWeight: '500'
                    }}>
                      {item.description}
                    </div>
                  </Link>
                )
              })}
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ backgroundColor: '#0a0e1a', minHeight: 'calc(100vh - 200px)' }}>
        {children}
      </main>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        
        * {
          box-sizing: border-box;
        }
        
        body {
          margin: 0;
          padding: 0;
          background: #0a0e1a;
          color: white;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11';
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
        }
        
        h1, h2, h3, h4, h5, h6 {
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
          font-weight: 700;
          letter-spacing: -0.025em;
        }
        
        code, pre {
          font-family: 'JetBrains Mono', Monaco, 'Cascadia Code', 'Roboto Mono', monospace;
          font-feature-settings: 'liga' 0;
        }
      `}</style>
    </div>
  )
}

export default Layout
