import React from 'react'
import { Link, useLocation } from 'react-router-dom'

function Layout({ children }) {
  const location = useLocation()

  const navigation = [
    { 
      name: 'Decision Engine', 
      href: '/enhanced', 
      fullName: 'Upload & Analyze',
      icon: '🚀',
      primary: true
    },
    { 
      name: 'Developer', 
      href: '/developer', 
      fullName: 'Pipeline Decisions',
      icon: '👨‍💻'
    },
    { 
      name: 'CISO', 
      href: '/ciso', 
      fullName: 'Executive Overview',
      icon: '👔'
    },
    { 
      name: 'Architect', 
      href: '/architect', 
      fullName: 'System Architecture',
      icon: '🏗️'
    },
    { 
      name: 'Install', 
      href: '/install', 
      fullName: 'Setup & CLI',
      icon: '📦'
    },
    { 
      name: 'Docs', 
      href: '/architecture', 
      fullName: 'Documentation',
      icon: '📚'
    }
  ]

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: 'white' }}>
      {/* Professional Enterprise Header */}
      <header style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.95) 100%)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
        backdropFilter: 'blur(10px)',
        position: 'sticky',
        top: 0,
        zIndex: 1000
      }}>
        <div style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '0 2rem'
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            height: '80px'
          }}>
            {/* Logo Section */}
            <Link to="/" style={{ display: 'flex', alignItems: 'center', textDecoration: 'none' }}>
              <div style={{
                width: '50px',
                height: '50px',
                background: 'linear-gradient(135deg, #2563eb 0%, #7c3aed 100%)',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '1rem',
                boxShadow: '0 8px 16px rgba(37, 99, 235, 0.3)'
              }}>
                <span style={{ fontSize: '1.5rem', color: 'white' }}>🛡️</span>
              </div>
              <div>
                <h1 style={{
                  fontSize: '1.75rem',
                  fontWeight: '800',
                  color: 'white',
                  margin: 0,
                  letterSpacing: '-0.025em'
                }}>
                  FixOps Enterprise
                </h1>
                <p style={{
                  fontSize: '0.75rem',
                  color: '#94a3b8',
                  margin: 0,
                  fontWeight: '500'
                }}>
                  DevSecOps Decision Engine
                </p>
              </div>
            </Link>

            {/* Enterprise Status */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                backgroundColor: 'rgba(22, 163, 74, 0.2)',
                border: '1px solid #16a34a',
                borderRadius: '20px',
                padding: '0.5rem 1rem'
              }}>
                <div style={{
                  width: '8px',
                  height: '8px',
                  backgroundColor: '#16a34a',
                  borderRadius: '50%',
                  marginRight: '0.5rem',
                  animation: 'pulse 2s infinite'
                }}></div>
                <span style={{
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: '#16a34a'
                }}>
                  ENTERPRISE READY
                </span>
              </div>
            </div>
          </div>

          {/* Enhanced Navigation */}
          <div style={{
            borderTop: '1px solid rgba(255, 255, 255, 0.1)',
            paddingTop: '0'
          }}>
            <nav style={{
              display: 'flex',
              gap: '0',
              overflowX: 'auto'
            }}>
              {navigation.map((item) => {
                const isActive = location.pathname === item.href
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    title={item.fullName}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: '1rem 1.5rem',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      textDecoration: 'none',
                      borderBottom: isActive ? '3px solid #2563eb' : '3px solid transparent',
                      backgroundColor: isActive ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
                      color: isActive ? '#60a5fa' : '#94a3b8',
                      transition: 'all 0.2s ease-in-out',
                      borderTop: isActive ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid transparent',
                      borderLeft: isActive ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid transparent',
                      borderRight: isActive ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid transparent',
                      borderTopLeftRadius: isActive ? '8px' : '0',
                      borderTopRightRadius: isActive ? '8px' : '0',
                      whiteSpace: 'nowrap',
                      gap: '0.5rem'
                    }}
                  >
                    <span style={{ fontSize: '1rem' }}>{item.icon}</span>
                    {item.name}
                    {item.primary && (
                      <span style={{
                        fontSize: '0.625rem',
                        backgroundColor: '#2563eb',
                        color: 'white',
                        padding: '0.125rem 0.375rem',
                        borderRadius: '8px',
                        fontWeight: '700'
                      }}>
                        CORE
                      </span>
                    )}
                  </Link>
                )
              })}
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ backgroundColor: '#0f172a' }}>
        {children}
      </main>

      {/* Professional Footer */}
      <footer style={{
        backgroundColor: 'rgba(30, 41, 59, 0.8)',
        borderTop: '1px solid rgba(255, 255, 255, 0.1)',
        padding: '2rem'
      }}>
        <div style={{
          maxWidth: '1600px',
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', marginBottom: '0.25rem', color: 'white' }}>
              FixOps Enterprise Decision Engine
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              AI-powered DevSecOps control plane with multi-LLM consensus • SSVC compliant
            </div>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              API: /api/v1/* • CLI: fixops-cli • Kubernetes Ready
            </div>
            <div style={{
              fontSize: '0.75rem',
              fontWeight: '600',
              color: '#16a34a',
              backgroundColor: 'rgba(22, 163, 74, 0.2)',
              padding: '0.25rem 0.75rem',
              borderRadius: '12px'
            }}>
              🆓 FREE TOOL
            </div>
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

export default Layout
