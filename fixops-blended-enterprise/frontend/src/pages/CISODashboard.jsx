import React from 'react'

function CISODashboard() {
  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1400px',
      margin: '0 auto'
    }}>
      
      {/* Perfect 3-Column Executive Metrics */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Risk Score - Red Theme */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '200px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
        }}>
          <div style={{
            width: '80px',
            height: '80px',
            backgroundColor: '#fecaca',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2.5rem'
          }}>
            🚨
          </div>
          <div style={{
            fontSize: '3.5rem',
            fontWeight: 'bold',
            color: '#dc2626',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            6.2
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            marginBottom: '0.25rem'
          }}>
            Risk Score
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#9ca3af',
            fontWeight: '500'
          }}>
            out of 10 (lower is better)
          </div>
        </div>

        {/* Critical Services - Yellow Theme */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '200px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
        }}>
          <div style={{
            width: '80px',
            height: '80px',
            backgroundColor: '#fef3c7',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2.5rem'
          }}>
            ⚠️
          </div>
          <div style={{
            fontSize: '3.5rem',
            fontWeight: 'bold',
            color: '#d97706',
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
            letterSpacing: '0.1em',
            marginBottom: '0.25rem'
          }}>
            Critical Services
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#9ca3af',
            fontWeight: '500'
          }}>
            requiring immediate attention
          </div>
        </div>

        {/* Compliance Score - Green Theme */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          textAlign: 'center',
          height: '200px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center'
        }}>
          <div style={{
            width: '80px',
            height: '80px',
            backgroundColor: '#dcfce7',
            borderRadius: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1rem',
            fontSize: '2.5rem'
          }}>
            ✅
          </div>
          <div style={{
            fontSize: '3.5rem',
            fontWeight: 'bold',
            color: '#16a34a',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            94%
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            marginBottom: '0.25rem'
          }}>
            Compliance Score
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#9ca3af',
            fontWeight: '500'
          }}>
            NIST SSDF & SOC2
          </div>
        </div>
      </div>

      {/* Executive Sections - Perfect Alignment */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Security Overview */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          height: '450px'
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
              backgroundColor: '#e0e7ff',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>📊</span>
            </div>
            <h2 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0
            }}>
              Security Overview
            </h2>
          </div>
          
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
                <span style={{ fontSize: '1.5rem', marginRight: '1rem', width: '24px', textAlign: 'center' }}>⏱️</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  Mean Time to Remediation
                </span>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#2563eb' }}>2.4h</div>
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
                <span style={{ fontSize: '1.5rem', marginRight: '1rem', width: '24px', textAlign: 'center' }}>👥</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  Security Team Size
                </span>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#2563eb' }}>12</div>
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
                <span style={{ fontSize: '1.5rem', marginRight: '1rem', width: '24px', textAlign: 'center' }}>🎯</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  Coverage Percentage
                </span>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#16a34a' }}>87%</div>
            </div>

            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '1.5rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0'
            }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '1.5rem', marginRight: '1rem', width: '24px', textAlign: 'center' }}>🤖</span>
                <span style={{ fontSize: '1.125rem', fontWeight: '600', color: '#374151' }}>
                  AI Automation Rate
                </span>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#16a34a' }}>89%</div>
            </div>
          </div>
        </div>

        {/* Compliance & Risk Assessment */}
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb',
          height: '450px'
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
              backgroundColor: '#fed7aa',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>🔍</span>
            </div>
            <h2 style={{ 
              fontSize: '1.75rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              margin: 0
            }}>
              Risk & Compliance
            </h2>
          </div>
          
          <div style={{ marginBottom: '2rem' }}>
            <h3 style={{ 
              fontSize: '1.25rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              marginBottom: '1rem' 
            }}>
              High-Risk Areas
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ 
                padding: '1rem 1.5rem', 
                backgroundColor: '#fef2f2', 
                borderRadius: '12px',
                border: '1px solid #fecaca',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>💳</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#dc2626' }}>
                    Payment Processing
                  </span>
                </div>
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
              <div style={{ 
                padding: '1rem 1.5rem', 
                backgroundColor: '#fef2f2', 
                borderRadius: '12px',
                border: '1px solid #fecaca',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🔐</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#dc2626' }}>
                    User Authentication
                  </span>
                </div>
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
              <div style={{ 
                padding: '1rem 1.5rem', 
                backgroundColor: '#fef2f2', 
                borderRadius: '12px',
                border: '1px solid #fecaca',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🌐</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#dc2626' }}>
                    API Gateway
                  </span>
                </div>
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
            </div>
          </div>
          
          <div>
            <h3 style={{ 
              fontSize: '1.25rem', 
              fontWeight: '700', 
              color: '#1f2937', 
              marginBottom: '1rem' 
            }}>
              Compliance Status
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ 
                padding: '1rem 1.5rem', 
                backgroundColor: '#f0fdf4', 
                borderRadius: '12px',
                border: '1px solid #bbf7d0',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>📋</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#16a34a' }}>
                    NIST SSDF
                  </span>
                </div>
                <span style={{ 
                  fontSize: '0.75rem', 
                  fontWeight: '700',
                  color: '#16a34a',
                  backgroundColor: '#dcfce7',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '20px'
                }}>
                  COMPLIANT
                </span>
              </div>
              <div style={{ 
                padding: '1rem 1.5rem', 
                backgroundColor: '#f0fdf4', 
                borderRadius: '12px',
                border: '1px solid #bbf7d0',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <span style={{ fontSize: '1.25rem', marginRight: '0.75rem' }}>🔒</span>
                  <span style={{ fontSize: '1rem', fontWeight: '600', color: '#16a34a' }}>
                    SOC2 Type II
                  </span>
                </div>
                <span style={{ 
                  fontSize: '0.75rem', 
                  fontWeight: '700',
                  color: '#16a34a',
                  backgroundColor: '#dcfce7',
                  padding: '0.25rem 0.75rem',
                  borderRadius: '20px'
                }}>
                  COMPLIANT
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Executive Summary - Premium Section */}
      <div style={{
        background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)',
        padding: '3rem',
        borderRadius: '20px',
        border: '1px solid #4b5563',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        color: 'white',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Background Pattern */}
        <div style={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: '300px',
          height: '300px',
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, transparent 70%)',
          zIndex: 0
        }}></div>
        
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
            <div style={{
              width: '72px',
              height: '72px',
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
              borderRadius: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1.5rem',
              backdropFilter: 'blur(10px)'
            }}>
              <span style={{ fontSize: '2.25rem' }}>📈</span>
            </div>
            <div>
              <h2 style={{ 
                fontSize: '2.25rem', 
                fontWeight: '800', 
                margin: 0,
                letterSpacing: '-0.025em'
              }}>
                Executive Summary
              </h2>
              <p style={{
                fontSize: '1.125rem',
                opacity: 0.8,
                margin: 0,
                fontWeight: '500'
              }}>
                Strategic security overview
              </p>
            </div>
          </div>
          
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '2rem',
            marginBottom: '2rem'
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
                24
              </div>
              <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Active Policies</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
                89%
              </div>
              <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Automated Decisions</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
                3
              </div>
              <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Policy Violations</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
                24/7
              </div>
              <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Monitoring</div>
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'rgba(255, 255, 255, 0.1)',
            padding: '1.5rem',
            borderRadius: '12px',
            backdropFilter: 'blur(10px)',
            border: '1px solid rgba(255, 255, 255, 0.2)'
          }}>
            <p style={{ 
              fontSize: '1.125rem', 
              margin: 0, 
              lineHeight: '1.7',
              fontWeight: '500'
            }}>
              <strong>Security Posture:</strong> The organization maintains a strong security posture with 94% compliance. 
              Critical focus areas include payment processing and authentication modules. 
              AI-driven correlation is reducing alert fatigue by 35%.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CISODashboard