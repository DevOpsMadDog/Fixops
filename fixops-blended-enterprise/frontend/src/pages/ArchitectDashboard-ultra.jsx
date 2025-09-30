import React from 'react'

function ArchitectDashboard() {
  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1400px',
      margin: '0 auto'
    }}>
      
      {/* Perfect 4-Column Architecture Metrics */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Services */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '180px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
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
            fontSize: '2rem'
          }}>
            🏗️
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#2563eb',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            47
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Services
          </div>
        </div>

        {/* Security Patterns */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '180px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
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
            fontSize: '2rem'
          }}>
            🛡️
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#16a34a',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            12
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Security Patterns
          </div>
        </div>

        {/* API Endpoints */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '180px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
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
            fontSize: '2rem'
          }}>
            🔗
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#7c3aed',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            234
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            API Endpoints
          </div>
        </div>

        {/* Code Quality */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '180px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
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
            fontSize: '2rem'
          }}>
            💻
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#059669',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            A+
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Code Quality
          </div>
        </div>
      </div>

      {/* Architecture Insights - Premium Full-Width */}
      <div style={{
        background: 'linear-gradient(135deg, #f3e8ff 0%, #e0e7ff 100%)',
        padding: '3rem',
        borderRadius: '20px',
        border: '2px solid #8b5cf6',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
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
                Architecture Insights
              </h2>
              <p style={{
                fontSize: '1.25rem',
                color: '#6b7280',
                margin: 0,
                fontWeight: '500'
              }}>
                Zero-trust security design patterns
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
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.5rem', marginBottom: '2rem' }}>
              <div style={{
                width: '32px',
                height: '32px',
                backgroundColor: '#dcfce7',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginTop: '0.25rem',
                flexShrink: 0
              }}>
                <div style={{ 
                  width: '12px', 
                  height: '12px', 
                  backgroundColor: '#16a34a', 
                  borderRadius: '50%'
                }}></div>
              </div>
              <div>
                <h3 style={{ 
                  fontSize: '1.5rem', 
                  fontWeight: '700', 
                  color: '#1f2937', 
                  margin: '0 0 1rem 0'
                }}>
                  Security-First Architecture Active
                </h3>
                <p style={{ 
                  fontSize: '1.125rem', 
                  color: '#6b7280', 
                  margin: '0 0 1.5rem 0', 
                  lineHeight: '1.7',
                  fontWeight: '500'
                }}>
                  Zero-trust architecture with layered security controls. API gateway enforcing 
                  authentication, rate limiting, and threat detection on all <strong style={{ color: '#2563eb' }}>234 endpoints</strong>.
                </p>
              </div>
            </div>
            
            {/* Architecture Stats */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
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
                  99.9%
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Uptime SLA
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '2.25rem',
                  fontWeight: 'bold',
                  color: '#16a34a',
                  marginBottom: '0.5rem'
                }}>
                  &lt;1s
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  API Response
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '2.25rem',
                  fontWeight: 'bold',
                  color: '#7c3aed',
                  marginBottom: '0.5rem'
                }}>
                  100%
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  TLS Coverage
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ArchitectDashboard