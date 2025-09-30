import React from 'react'

function DeveloperDashboard() {
  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1400px',
      margin: '0 auto'
    }}>
      
      {/* Perfect 4-Column Metrics Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Total Findings - Blue Theme */}
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
          alignItems: 'center',
          transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
          cursor: 'pointer'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'translateY(-4px)'
          e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'translateY(0)'
          e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
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
            🛡️
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#1f2937',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            127
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Total Findings
          </div>
        </div>

        {/* Open Findings - Yellow Theme */}
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
          alignItems: 'center',
          transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
          cursor: 'pointer'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'translateY(-4px)'
          e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'translateY(0)'
          e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
        }}>
          <div style={{
            width: '72px',
            height: '72px',
            backgroundColor: '#fef3c7',
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
            color: '#d97706',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            34
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Open Findings
          </div>
        </div>

        {/* Critical - Red Theme */}
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
          alignItems: 'center',
          transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
          cursor: 'pointer'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'translateY(-4px)'
          e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'translateY(0)'
          e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
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
            🐛
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#dc2626',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            8
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Critical
          </div>
        </div>

        {/* Fixed - Green Theme */}
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
          alignItems: 'center',
          transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
          cursor: 'pointer'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'translateY(-4px)'
          e.currentTarget.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'translateY(0)'
          e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
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
            93
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Fixed
          </div>
        </div>
      </div>

      {/* Perfect 2-Column Grid - Equal Heights */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Performance Metrics - Left Column */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          height: '400px'
        }}>
          {/* Section Header */}
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
              backgroundColor: '#ddd6fe',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>⚡</span>
            </div>
            <h2 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0,
              letterSpacing: '-0.025em'
            }}>
              Performance Metrics
            </h2>
          </div>
          
          {/* Perfectly Aligned Metrics */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.5rem',
              backgroundColor: '#f9fafb',
              borderRadius: '12px',
              border: '1px solid #f3f4f6'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ 
                  fontSize: '1.5rem', 
                  marginRight: '1rem',
                  width: '24px',
                  textAlign: 'center'
                }}>🎯</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  Hot Path Latency
                </span>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#16a34a' }}>
                  285μs
                </div>
                <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '500' }}>
                  (target: 299μs)
                </div>
              </div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.5rem',
              backgroundColor: '#f9fafb',
              borderRadius: '12px',
              border: '1px solid #f3f4f6'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ 
                  fontSize: '1.5rem', 
                  marginRight: '1rem',
                  width: '24px',
                  textAlign: 'center'
                }}>📊</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  Correlated Findings
                </span>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#2563eb' }}>45</div>
            </div>
            
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.5rem',
              backgroundColor: '#f9fafb',
              borderRadius: '12px',
              border: '1px solid #f3f4f6'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ 
                  fontSize: '1.5rem', 
                  marginRight: '1rem',
                  width: '24px',
                  textAlign: 'center'
                }}>📈</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  Noise Reduction
                </span>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#16a34a' }}>35%</div>
            </div>
          </div>
        </div>

        {/* Recent Activity - Right Column */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          height: '400px'
        }}>
          {/* Section Header */}
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
              backgroundColor: '#fed7aa',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>🕒</span>
            </div>
            <h2 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0,
              letterSpacing: '-0.025em'
            }}>
              Recent Activity
            </h2>
          </div>
          
          {/* Perfectly Aligned Activity Items */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                backgroundColor: '#dcfce7',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.25rem',
                flexShrink: 0
              }}>
                🐛
              </div>
              <div style={{ flex: 1 }}>
                <p style={{ 
                  fontSize: '1.125rem', 
                  fontWeight: '700', 
                  color: '#1f2937', 
                  margin: '0 0 0.5rem 0',
                  lineHeight: '1.3'
                }}>
                  SQL Injection fixed in user-service
                </p>
                <p style={{ 
                  fontSize: '1rem', 
                  color: '#6b7280', 
                  margin: '0 0 0.5rem 0',
                  fontWeight: '500'
                }}>
                  Critical vulnerability resolved
                </p>
                <p style={{ fontSize: '0.875rem', color: '#9ca3af', margin: 0, fontWeight: '600' }}>
                  2h ago
                </p>
              </div>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                backgroundColor: '#fef3c7',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.25rem',
                flexShrink: 0
              }}>
                ⚠️
              </div>
              <div style={{ flex: 1 }}>
                <p style={{ 
                  fontSize: '1.125rem', 
                  fontWeight: '700', 
                  color: '#1f2937', 
                  margin: '0 0 0.5rem 0',
                  lineHeight: '1.3'
                }}>
                  XSS vulnerability correlated (3 findings)
                </p>
                <p style={{ 
                  fontSize: '1rem', 
                  color: '#6b7280', 
                  margin: '0 0 0.5rem 0',
                  fontWeight: '500'
                }}>
                  Similar issues found across services
                </p>
                <p style={{ fontSize: '0.875rem', color: '#9ca3af', margin: 0, fontWeight: '600' }}>
                  4h ago
                </p>
              </div>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                backgroundColor: '#dbeafe',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.25rem',
                flexShrink: 0
              }}>
                ✅
              </div>
              <div style={{ flex: 1 }}>
                <p style={{ 
                  fontSize: '1.125rem', 
                  fontWeight: '700', 
                  color: '#1f2937', 
                  margin: '0 0 0.5rem 0',
                  lineHeight: '1.3'
                }}>
                  Policy decision: ALLOW deployment
                </p>
                <p style={{ 
                  fontSize: '1rem', 
                  color: '#6b7280', 
                  margin: '0 0 0.5rem 0',
                  fontWeight: '500'
                }}>
                  Security review completed
                </p>
                <p style={{ fontSize: '0.875rem', color: '#9ca3af', margin: 0, fontWeight: '600' }}>
                  6h ago
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* AI Insights - Full Width Premium Section */}
      <div style={{
        background: 'linear-gradient(135deg, #dbeafe 0%, #e0e7ff 100%)',
        padding: '3rem',
        borderRadius: '20px',
        border: '2px solid #2563eb',
        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Decorative Background Elements */}
        <div style={{
          position: 'absolute',
          top: '-50px',
          right: '-50px',
          width: '200px',
          height: '200px',
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          borderRadius: '50%',
          zIndex: 0
        }}></div>
        
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
            <div style={{
              width: '72px',
              height: '72px',
              backgroundColor: 'white',
              borderRadius: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1.5rem',
              boxShadow: '0 8px 16px -4px rgba(0, 0, 0, 0.1)'
            }}>
              <span style={{ fontSize: '2.25rem' }}>🤖</span>
            </div>
            <div>
              <h2 style={{ 
                fontSize: '2.25rem', 
                fontWeight: '800', 
                color: '#1f2937', 
                margin: 0,
                letterSpacing: '-0.025em'
              }}>
                AI-Powered Insights
              </h2>
              <p style={{
                fontSize: '1.125rem',
                color: '#6b7280',
                margin: 0,
                fontWeight: '500'
              }}>
                Advanced correlation and analysis
              </p>
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '2.5rem',
            borderRadius: '16px',
            border: '1px solid rgba(37, 99, 235, 0.2)',
            boxShadow: '0 8px 16px -4px rgba(0, 0, 0, 0.1)'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.5rem' }}>
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
                  borderRadius: '50%',
                  animation: 'pulse 2s infinite'
                }}></div>
              </div>
              <div>
                <h3 style={{ 
                  fontSize: '1.5rem', 
                  fontWeight: '700', 
                  color: '#1f2937', 
                  margin: '0 0 1rem 0',
                  letterSpacing: '-0.025em'
                }}>
                  Correlation Engine Active
                </h3>
                <p style={{ 
                  fontSize: '1.125rem', 
                  color: '#6b7280', 
                  margin: 0, 
                  lineHeight: '1.7',
                  fontWeight: '500'
                }}>
                  Automatically correlating security findings and reducing noise by <strong style={{ color: '#16a34a' }}>35%</strong>. 
                  Last analysis: <strong style={{ color: '#2563eb' }}>45 findings</strong> correlated into <strong style={{ color: '#2563eb' }}>12 actionable items</strong>.
                </p>
                
                {/* Performance Stats */}
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(3, 1fr)',
                  gap: '1.5rem',
                  marginTop: '2rem',
                  padding: '1.5rem',
                  backgroundColor: '#f8fafc',
                  borderRadius: '12px',
                  border: '1px solid #e5e7eb'
                }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.25rem' }}>
                      35%
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                      Noise Reduced
                    </div>
                  </div>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.25rem' }}>
                      12
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                      Action Items
                    </div>
                  </div>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#dc2626', marginBottom: '0.25rem' }}>
                      2.4h
                    </div>
                    <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                      Avg Resolution
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DeveloperDashboard