import React from 'react'

function ArchitectDashboard() {
  console.log('🔥 Architect Dashboard component rendering!')
  
  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#f8fafc',
      padding: '2rem 1rem'
    }}>
      <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ marginBottom: '3rem', textAlign: 'center' }}>
          <h1 style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#1f2937',
            marginBottom: '0.75rem',
            letterSpacing: '-0.025em'
          }}>
            Architect Dashboard
          </h1>
          <p style={{ 
            color: '#6b7280', 
            fontSize: '1.25rem',
            maxWidth: '600px',
            margin: '0 auto',
            lineHeight: '1.6'
          }}>
            System architecture insights and security design patterns
          </p>
        </div>

        {/* Architecture Metrics Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '2rem',
          marginBottom: '3rem'
        }}>
          {/* Services Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            border: '1px solid #e5e7eb',
            height: '140px',
            display: 'flex',
            alignItems: 'center'
          }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              width: '100%'
            }}>
              <div>
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#6b7280', 
                  marginBottom: '0.5rem',
                  fontWeight: '500',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Services
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#1f2937',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  47
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  microservices
                </p>
              </div>
              <div style={{
                width: '60px',
                height: '60px',
                backgroundColor: '#dbeafe',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem'
              }}>
                🏗️
              </div>
            </div>
          </div>

          {/* Security Patterns Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            border: '1px solid #e5e7eb',
            height: '140px',
            display: 'flex',
            alignItems: 'center'
          }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              width: '100%'
            }}>
              <div>
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#6b7280', 
                  marginBottom: '0.5rem',
                  fontWeight: '500',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Security Patterns
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#16a34a',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  12
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  implemented
                </p>
              </div>
              <div style={{
                width: '60px',
                height: '60px',
                backgroundColor: '#dcfce7',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem'
              }}>
                🛡️
              </div>
            </div>
          </div>

          {/* API Endpoints Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            border: '1px solid #e5e7eb',
            height: '140px',
            display: 'flex',
            alignItems: 'center'
          }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              width: '100%'
            }}>
              <div>
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#6b7280', 
                  marginBottom: '0.5rem',
                  fontWeight: '500',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  API Endpoints
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#2563eb',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  234
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  secured endpoints
                </p>
              </div>
              <div style={{
                width: '60px',
                height: '60px',
                backgroundColor: '#e0e7ff',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem'
              }}>
                🔗
              </div>
            </div>
          </div>

          {/* Code Quality Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            border: '1px solid #e5e7eb',
            height: '140px',
            display: 'flex',
            alignItems: 'center'
          }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              width: '100%'
            }}>
              <div>
                <p style={{ 
                  fontSize: '0.875rem', 
                  color: '#6b7280', 
                  marginBottom: '0.5rem',
                  fontWeight: '500',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Code Quality
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#16a34a',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  A+
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  security grade
                </p>
              </div>
              <div style={{
                width: '60px',
                height: '60px',
                backgroundColor: '#dcfce7',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem'
              }}>
                💻
              </div>
            </div>
          </div>
        </div>

        {/* Architecture Insights */}
        <div style={{
          background: 'linear-gradient(135deg, #f3e8ff 0%, #e0e7ff 100%)',
          padding: '2.5rem',
          borderRadius: '20px',
          border: '2px solid #8b5cf6',
          boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1.5rem' }}>
            <div style={{
              width: '56px',
              height: '56px',
              backgroundColor: 'white',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
            }}>
              <span style={{ fontSize: '1.75rem' }}>🏛️</span>
            </div>
            <h3 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0,
              letterSpacing: '-0.025em'
            }}>
              Architecture Insights
            </h3>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            border: '1px solid rgba(139, 92, 246, 0.2)',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '24px',
                height: '24px',
                backgroundColor: '#dcfce7',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginTop: '0.25rem',
                flexShrink: 0
              }}>
                <div style={{ 
                  width: '8px', 
                  height: '8px', 
                  backgroundColor: '#16a34a', 
                  borderRadius: '50%'
                }}></div>
              </div>
              <div>
                <h4 style={{ 
                  fontSize: '1.125rem', 
                  fontWeight: '700', 
                  color: '#1f2937', 
                  margin: '0 0 0.75rem 0' 
                }}>
                  Security-First Architecture Active
                </h4>
                <p style={{ 
                  fontSize: '1rem', 
                  color: '#6b7280', 
                  margin: 0, 
                  lineHeight: '1.6',
                  fontWeight: '500'
                }}>
                  Zero-trust architecture with layered security controls. API gateway enforcing 
                  authentication, rate limiting, and threat detection on all 234 endpoints.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ArchitectDashboard