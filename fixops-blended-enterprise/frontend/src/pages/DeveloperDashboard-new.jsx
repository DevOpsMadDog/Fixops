import React from 'react'

function DeveloperDashboard() {
  console.log('🔥 DeveloperDashboard component rendering!')
  
  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#f8fafc',
      padding: '2rem'
    }}>
      {/* Debug indicator */}
      <div style={{
        backgroundColor: '#dcfce7',
        border: '2px solid #22c55e',
        color: '#166534',
        padding: '1rem',
        borderRadius: '8px',
        marginBottom: '2rem',
        fontSize: '18px',
        fontWeight: 'bold'
      }}>
        🎉 NEW DASHBOARD COMPONENT IS WORKING!
      </div>
      
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{
            fontSize: '2.5rem',
            fontWeight: 'bold',
            color: '#1f2937',
            marginBottom: '0.5rem'
          }}>
            FixOps Enterprise Dashboard
          </h1>
          <p style={{ color: '#6b7280', fontSize: '1.1rem' }}>
            Security findings and performance metrics for your applications
          </p>
        </div>

        {/* Metrics Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '1.5rem',
          marginBottom: '2rem'
        }}>
          {/* Total Findings Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '12px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.25rem' }}>Total Findings</p>
                <p style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937' }}>127</p>
              </div>
              <div style={{
                width: '40px',
                height: '40px',
                backgroundColor: '#dbeafe',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.2rem'
              }}>
                🛡️
              </div>
            </div>
          </div>

          {/* Open Findings Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '12px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.25rem' }}>Open Findings</p>
                <p style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937' }}>34</p>
              </div>
              <div style={{
                width: '40px',
                height: '40px',
                backgroundColor: '#fef3c7',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.2rem'
              }}>
                ⚠️
              </div>
            </div>
          </div>

          {/* Critical Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '12px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.25rem' }}>Critical</p>
                <p style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937' }}>8</p>
              </div>
              <div style={{
                width: '40px',
                height: '40px',
                backgroundColor: '#fecaca',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.2rem'
              }}>
                🐛
              </div>
            </div>
          </div>

          {/* Fixed Card */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '12px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.25rem' }}>Fixed</p>
                <p style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937' }}>93</p>
              </div>
              <div style={{
                width: '40px',
                height: '40px',
                backgroundColor: '#dcfce7',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.2rem'
              }}>
                ✅
              </div>
            </div>
          </div>
        </div>

        {/* Performance Section */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
          gap: '1.5rem'
        }}>
          {/* Performance Metrics */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '12px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{
                width: '32px',
                height: '32px',
                backgroundColor: '#ddd6fe',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '0.75rem'
              }}>
                ⚡
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '600', color: '#1f2937', margin: 0 }}>
                Performance Metrics
              </h3>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.75rem',
                backgroundColor: '#f9fafb',
                borderRadius: '8px'
              }}>
                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#374151' }}>
                  🎯 Hot Path Latency
                </span>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#16a34a' }}>
                    285μs
                  </span>
                  <br />
                  <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>(target: 299μs)</span>
                </div>
              </div>
              
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.75rem',
                backgroundColor: '#f9fafb',
                borderRadius: '8px'
              }}>
                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#374151' }}>
                  📊 Correlated Findings
                </span>
                <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#2563eb' }}>45</span>
              </div>
              
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.75rem',
                backgroundColor: '#f9fafb',
                borderRadius: '8px'
              }}>
                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#374151' }}>
                  📈 Noise Reduction
                </span>
                <span style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#16a34a' }}>35%</span>
              </div>
            </div>
          </div>

          {/* Recent Activity */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '12px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{
                width: '32px',
                height: '32px',
                backgroundColor: '#fed7aa',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '0.75rem'
              }}>
                🕒
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '600', color: '#1f2937', margin: 0 }}>
                Recent Activity
              </h3>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  backgroundColor: '#dcfce7',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem'
                }}>
                  🐛
                </div>
                <div style={{ flex: 1 }}>
                  <p style={{ fontSize: '0.875rem', fontWeight: '500', color: '#1f2937', margin: '0 0 0.25rem 0' }}>
                    SQL Injection fixed in user-service
                  </p>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 0.25rem 0' }}>
                    Critical vulnerability resolved
                  </p>
                  <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>2h ago</p>
                </div>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  backgroundColor: '#fef3c7',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem'
                }}>
                  ⚠️
                </div>
                <div style={{ flex: 1 }}>
                  <p style={{ fontSize: '0.875rem', fontWeight: '500', color: '#1f2937', margin: '0 0 0.25rem 0' }}>
                    XSS vulnerability correlated (3 findings)
                  </p>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: '0 0 0.25rem 0' }}>
                    Similar issues found across services
                  </p>
                  <p style={{ fontSize: '0.75rem', color: '#9ca3af', margin: 0 }}>4h ago</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* AI Insights */}
        <div style={{
          background: 'linear-gradient(135deg, #dbeafe 0%, #e0e7ff 100%)',
          padding: '1.5rem',
          borderRadius: '12px',
          border: '1px solid #3b82f6',
          marginTop: '2rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{
              width: '32px',
              height: '32px',
              backgroundColor: 'white',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '0.75rem'
            }}>
              🤖
            </div>
            <h3 style={{ fontSize: '1.125rem', fontWeight: '600', color: '#1f2937', margin: 0 }}>
              AI-Powered Insights
            </h3>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '1rem',
            borderRadius: '8px',
            border: '1px solid rgba(59, 130, 246, 0.2)'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
              <div style={{
                width: '16px',
                height: '16px',
                backgroundColor: '#dcfce7',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginTop: '0.125rem'
              }}>
                <div style={{ width: '6px', height: '6px', backgroundColor: '#16a34a', borderRadius: '50%' }}></div>
              </div>
              <div>
                <h4 style={{ fontSize: '0.875rem', fontWeight: '500', color: '#1f2937', margin: '0 0 0.25rem 0' }}>
                  Correlation Engine Active
                </h4>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0, lineHeight: '1.4' }}>
                  Automatically correlating security findings and reducing noise by 35%. 
                  Last analysis: 45 findings correlated into 12 actionable items.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DeveloperDashboard