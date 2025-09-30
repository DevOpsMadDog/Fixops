import React from 'react'

function IncidentsPage() {
  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1400px',
      margin: '0 auto'
    }}>
      
      {/* Header */}
      <div style={{ marginBottom: '3rem', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '3rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.75rem',
          letterSpacing: '-0.025em'
        }}>
          Security Incidents
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.25rem',
          maxWidth: '600px',
          margin: '0 auto',
          lineHeight: '1.6'
        }}>
          Track and manage security incidents across your services
        </p>
      </div>

      {/* Incident Summary Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Active Incidents */}
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
            backgroundColor: '#fecaca',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2rem'
          }}>
            🚨
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#dc2626',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            3
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Active Incidents
          </div>
        </div>

        {/* Resolved This Month */}
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
            ✅
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#16a34a',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            27
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Resolved This Month
          </div>
        </div>

        {/* Average Resolution Time */}
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
            ⏱️
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#2563eb',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            2.4h
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Avg Resolution Time
          </div>
        </div>
      </div>

      {/* Recent Incidents Table */}
      <div style={{
        backgroundColor: 'white',
        padding: '2.5rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        border: '1px solid #e5e7eb'
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
            backgroundColor: '#fef3c7',
            borderRadius: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginRight: '1rem'
          }}>
            <span style={{ fontSize: '1.75rem' }}>⚠️</span>
          </div>
          <h2 style={{ 
            fontSize: '1.75rem', 
            fontWeight: '700', 
            color: '#1f2937', 
            margin: 0
          }}>
            Recent Security Incidents
          </h2>
        </div>
        
        {/* Incident List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '1rem',
            padding: '1.5rem',
            backgroundColor: '#fef2f2',
            borderRadius: '12px',
            border: '1px solid #fecaca'
          }}>
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
              flexShrink: 0
            }}>
              🐛
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                  SQL Injection in Payment Service
                </h3>
                <span style={{
                  fontSize: '0.75rem',
                  fontWeight: '700',
                  color: '#dc2626',
                  backgroundColor: '#fee2e2',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '20px'
                }}>
                  CRITICAL
                </span>
              </div>
              <p style={{ fontSize: '1rem', color: '#6b7280', margin: '0 0 0.5rem 0' }}>
                SQL injection vulnerability discovered in payment processing endpoint
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>👤 Sarah Chen</span>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>🕒 2 hours ago</span>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>🏢 payment-service</span>
              </div>
            </div>
          </div>
          
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '1rem',
            padding: '1.5rem',
            backgroundColor: '#fef3c7',
            borderRadius: '12px',
            border: '1px solid #fed7aa'
          }}>
            <div style={{
              width: '48px',
              height: '48px',
              backgroundColor: '#d97706',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.25rem',
              color: 'white',
              flexShrink: 0
            }}>
              ⚠️
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                  XSS Vulnerability Cluster
                </h3>
                <span style={{
                  fontSize: '0.75rem',
                  fontWeight: '700',
                  color: '#d97706',
                  backgroundColor: '#fef3c7',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '20px'
                }}>
                  HIGH
                </span>
              </div>
              <p style={{ fontSize: '1rem', color: '#6b7280', margin: '0 0 0.5rem 0' }}>
                Multiple XSS findings correlated across user input forms
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>👤 Mike Johnson</span>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>🕒 4 hours ago</span>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>🏢 web-app</span>
              </div>
            </div>
          </div>
          
          <div style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '1rem',
            padding: '1.5rem',
            backgroundColor: '#f0fdf4',
            borderRadius: '12px',
            border: '1px solid #bbf7d0'
          }}>
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
              flexShrink: 0
            }}>
              ✅
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                  Hardcoded API Key
                </h3>
                <span style={{
                  fontSize: '0.75rem',
                  fontWeight: '700',
                  color: '#16a34a',
                  backgroundColor: '#dcfce7',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '20px'
                }}>
                  RESOLVED
                </span>
              </div>
              <p style={{ fontSize: '1rem', color: '#6b7280', margin: '0 0 0.5rem 0' }}>
                Hardcoded API key found in configuration files
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>👤 Alex Rodriguez</span>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>🕒 1 day ago</span>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', fontWeight: '600' }}>🏢 auth-service</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default IncidentsPage