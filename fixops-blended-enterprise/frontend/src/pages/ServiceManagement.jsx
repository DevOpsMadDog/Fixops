import React from 'react'

function ServiceManagement() {
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
          Service Management
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.25rem',
          maxWidth: '600px',
          margin: '0 auto',
          lineHeight: '1.6'
        }}>
          Monitor and manage your microservices ecosystem
        </p>
      </div>

      {/* Service Status Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minMax(280px, 1fr))',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Total Services */}
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
            Total Services
          </div>
        </div>

        {/* Healthy Services */}
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
            44
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Healthy Services
          </div>
        </div>

        {/* At Risk */}
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
            ⚠️
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
            At Risk
          </div>
        </div>

        {/* Security Score */}
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
            A+
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Security Score
          </div>
        </div>
      </div>

      {/* Service Overview */}
      <div style={{
        background: 'linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)',
        padding: '3rem',
        borderRadius: '20px',
        border: '2px solid #16a34a',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
      }}>
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
            <span style={{ fontSize: '2.5rem' }}>🌐</span>
          </div>
          <div>
            <h2 style={{ 
              fontSize: '2.5rem', 
              fontWeight: '800', 
              color: '#1f2937', 
              margin: 0,
              letterSpacing: '-0.025em'
            }}>
              Service Ecosystem
            </h2>
            <p style={{
              fontSize: '1.25rem',
              color: '#6b7280',
              margin: 0,
              fontWeight: '500'
            }}>
              Distributed microservices architecture
            </p>
          </div>
        </div>
        
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          border: '1px solid rgba(22, 163, 74, 0.2)',
          boxShadow: '0 8px 16px -4px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '2rem',
            textAlign: 'center'
          }}>
            <div>
              <div style={{ fontSize: '2.25rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>
                99.9%
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Uptime SLA</div>
            </div>
            <div>
              <div style={{ fontSize: '2.25rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>
                &lt;500ms
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Avg Response</div>
            </div>
            <div>
              <div style={{ fontSize: '2.25rem', fontWeight: 'bold', color: '#7c3aed', marginBottom: '0.5rem' }}>
                24/7
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Monitoring</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ServiceManagement