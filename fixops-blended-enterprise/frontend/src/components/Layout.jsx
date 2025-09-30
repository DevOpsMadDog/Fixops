import React from 'react'
import { Link, useLocation } from 'react-router-dom'

function Layout({ children }) {
  const location = useLocation()

  const navigation = [
    { name: 'Developer', href: '/developer', fullName: 'Developer Dashboard' },
    { name: 'CISO', href: '/ciso', fullName: 'CISO Dashboard' },
    { name: 'Architect', href: '/architect', fullName: 'Architect Dashboard' },
    { name: 'Upload', href: '/upload', fullName: 'Scan Upload' },
    { name: 'Marketplace', href: '/marketplace', fullName: 'Security Marketplace' },
    { name: 'Incidents', href: '/incidents', fullName: 'Incidents' },
    { name: 'Analytics', href: '/analytics', fullName: 'Analytics' },
    { name: 'Services', href: '/services', fullName: 'Services' },
  ]

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f8fafc' }}>
      {/* Professional Header */}
      <header style={{
        backgroundColor: 'white',
        borderBottom: '1px solid #e5e7eb',
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)'
      }}>
        <div style={{
          maxWidth: '1400px',
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
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{
                width: '48px',
                height: '48px',
                backgroundColor: '#2563eb',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '1rem'
              }}>
                <span style={{ fontSize: '1.5rem', color: 'white' }}>🛡️</span>
              </div>
              <div>
                <h1 style={{
                  fontSize: '1.5rem',
                  fontWeight: 'bold',
                  color: '#1f2937',
                  margin: 0,
                  letterSpacing: '-0.025em'
                }}>
                  FixOps Enterprise
                </h1>
                <p style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  margin: 0,
                  fontWeight: '500'
                }}>
                  DevSecOps Control Plane
                </p>
              </div>
            </div>

            {/* FixOps Free Tool Indicator */}
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                backgroundColor: '#f0fdf4',
                padding: '0.5rem 1rem',
                borderRadius: '20px',
                border: '1px solid #bbf7d0'
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
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  color: '#16a34a'
                }}>
                  🆓 Free Decision Engine
                </span>
              </div>
            </div>
          </div>

          {/* Professional Tab Navigation */}
          <div style={{
            borderTop: '1px solid #f3f4f6',
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
                      padding: '1rem 2rem',
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      textDecoration: 'none',
                      borderBottom: isActive ? '3px solid #2563eb' : '3px solid transparent',
                      backgroundColor: isActive ? '#f8fafc' : 'transparent',
                      color: isActive ? '#2563eb' : '#6b7280',
                      transition: 'all 0.2s ease-in-out',
                      borderTop: isActive ? '1px solid #e5e7eb' : '1px solid transparent',
                      borderLeft: isActive ? '1px solid #e5e7eb' : '1px solid transparent',
                      borderRight: isActive ? '1px solid #e5e7eb' : '1px solid transparent',
                      borderTopLeftRadius: isActive ? '8px' : '0',
                      borderTopRightRadius: isActive ? '8px' : '0',
                      marginTop: isActive ? '0' : '0',
                      position: 'relative',
                      whiteSpace: 'nowrap'
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) {
                        e.target.style.backgroundColor = '#f9fafb'
                        e.target.style.color = '#374151'
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) {
                        e.target.style.backgroundColor = 'transparent'
                        e.target.style.color = '#6b7280'
                      }
                    }}
                  >
                    {item.name}
                  </Link>
                )
              })}
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{
        minHeight: 'calc(100vh - 140px)',
        backgroundColor: '#f8fafc'
      }}>
        {children}
      </main>
    </div>
  )
}

export default Layout