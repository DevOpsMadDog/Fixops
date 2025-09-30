import React from 'react'

function CISODashboard() {
  console.log('🔥 CISO Dashboard component rendering!')
  
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
            CISO Dashboard
          </h1>
          <p style={{ 
            color: '#6b7280', 
            fontSize: '1.25rem',
            maxWidth: '600px',
            margin: '0 auto',
            lineHeight: '1.6'
          }}>
            Executive security risk overview and compliance status
          </p>
        </div>

        {/* Risk Metrics Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '2rem',
          marginBottom: '3rem'
        }}>
          {/* Risk Score Card */}
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
                  Risk Score
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#dc2626',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  6.2
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  out of 10 (lower is better)
                </p>
              </div>
              <div style={{
                width: '60px',
                height: '60px',
                backgroundColor: '#fecaca',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem'
              }}>
                🚨
              </div>
            </div>
          </div>

          {/* Critical Services Card */}
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
                  Critical Services
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#dc2626',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  3
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  requiring immediate attention
                </p>
              </div>
              <div style={{
                width: '60px',
                height: '60px',
                backgroundColor: '#fef3c7',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem'
              }}>
                ⚠️
              </div>
            </div>
          </div>

          {/* Compliance Score Card */}
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
                  Compliance Score
                </p>
                <p style={{ 
                  fontSize: '2.5rem', 
                  fontWeight: 'bold', 
                  color: '#16a34a',
                  margin: 0,
                  lineHeight: '1'
                }}>
                  94%
                </p>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0 }}>
                  NIST SSDF & SOC2
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
                ✅
              </div>
            </div>
          </div>
        </div>

        {/* Security Metrics & Risk Assessment Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))',
          gap: '2rem',
          marginBottom: '3rem'
        }}>
          {/* Security Metrics */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            border: '1px solid #e5e7eb',
            minHeight: '350px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                backgroundColor: '#e0e7ff',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '1rem'
              }}>
                <span style={{ fontSize: '1.5rem' }}>📊</span>
              </div>
              <h3 style={{ 
                fontSize: '1.5rem', 
                fontWeight: '700', 
                color: '#1f2937', 
                margin: 0,
                letterSpacing: '-0.025em'
              }}>
                Security Metrics
              </h3>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '1.25rem',
                backgroundColor: '#f9fafb',
                borderRadius: '12px',
                border: '1px solid #f3f4f6'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>⏱️</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                    Mean Time to Remediation
                  </span>
                </div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#2563eb' }}>2.4h</div>
              </div>
              
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '1.25rem',
                backgroundColor: '#f9fafb',
                borderRadius: '12px',
                border: '1px solid #f3f4f6'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>👥</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                    Security Team Size
                  </span>
                </div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#2563eb' }}>12</div>
              </div>
              
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '1.25rem',
                backgroundColor: '#f9fafb',
                borderRadius: '12px',
                border: '1px solid #f3f4f6'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🎯</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
                    Coverage Percentage
                  </span>
                </div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#16a34a' }}>87%</div>
              </div>
            </div>
          </div>

          {/* Risk Assessment */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            border: '1px solid #e5e7eb',
            minHeight: '350px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                backgroundColor: '#fed7aa',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '1rem'
              }}>
                <span style={{ fontSize: '1.5rem' }}>🔍</span>
              </div>
              <h3 style={{ 
                fontSize: '1.5rem', 
                fontWeight: '700', 
                color: '#1f2937', 
                margin: 0,
                letterSpacing: '-0.025em'
              }}>
                Risk Assessment & Compliance
              </h3>
            </div>
            
            <div style={{ marginBottom: '2rem' }}>
              <h4 style={{ 
                fontSize: '1rem', 
                fontWeight: '600', 
                color: '#1f2937', 
                marginBottom: '1rem' 
              }}>
                High-Risk Areas
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ 
                  padding: '0.75rem', 
                  backgroundColor: '#fef2f2', 
                  borderRadius: '8px',
                  border: '1px solid #fecaca'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#dc2626' }}>
                    💳 Payment Processing Service
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#6b7280', marginLeft: '0.5rem' }}>Critical</span>
                </div>
                <div style={{ 
                  padding: '0.75rem', 
                  backgroundColor: '#fef2f2', 
                  borderRadius: '8px',
                  border: '1px solid #fecaca'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#dc2626' }}>
                    🔐 User Authentication Module
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#6b7280', marginLeft: '0.5rem' }}>High</span>
                </div>
                <div style={{ 
                  padding: '0.75rem', 
                  backgroundColor: '#fef2f2', 
                  borderRadius: '8px',
                  border: '1px solid #fecaca'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#dc2626' }}>
                    🌐 API Gateway
                  </span>
                  <span style={{ fontSize: '0.75rem', color: '#6b7280', marginLeft: '0.5rem' }}>High</span>
                </div>
              </div>
            </div>
            
            <div>
              <h4 style={{ 
                fontSize: '1rem', 
                fontWeight: '600', 
                color: '#1f2937', 
                marginBottom: '1rem' 
              }}>
                Compliance Status
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ 
                  padding: '0.75rem', 
                  backgroundColor: '#f0fdf4', 
                  borderRadius: '8px',
                  border: '1px solid #bbf7d0',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#16a34a' }}>
                    📋 NIST SSDF
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#16a34a' }}>Compliant</span>
                </div>
                <div style={{ 
                  padding: '0.75rem', 
                  backgroundColor: '#f0fdf4', 
                  borderRadius: '8px',
                  border: '1px solid #bbf7d0',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#16a34a' }}>
                    🔒 SOC2 Type II
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#16a34a' }}>Compliant</span>
                </div>
                <div style={{ 
                  padding: '0.75rem', 
                  backgroundColor: '#fef3c7', 
                  borderRadius: '8px',
                  border: '1px solid #fed7aa',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#d97706' }}>
                    💳 PCI DSS
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 'bold', color: '#d97706' }}>Review Required</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Policy Automation Section */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '20px',
          boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
          border: '1px solid #e5e7eb'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
            <div style={{
              width: '56px',
              height: '56px',
              backgroundColor: '#ddd6fe',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>🤖</span>
            </div>
            <h3 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0,
              letterSpacing: '-0.025em'
            }}>
              Policy Automation
            </h3>
          </div>
          
          <div style={{ 
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '2rem'
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>
                24
              </div>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '500' }}>Active Policies</p>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>
                89%
              </div>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '500' }}>Automated Decisions</p>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#dc2626', marginBottom: '0.5rem' }}>
                3
              </div>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '500' }}>Policy Violations</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CISODashboard