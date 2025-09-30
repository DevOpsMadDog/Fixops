import React from 'react'

function AnalyticsPage() {
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
          Security Analytics
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.25rem',
          maxWidth: '600px',
          margin: '0 auto',
          lineHeight: '1.6'
        }}>
          Comprehensive security metrics and trend analysis
        </p>
      </div>

      {/* Analytics Metrics */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minItems(280px, 1fr))',
        gap: '2rem',
        marginBottom: '3rem'
      }}>
        {/* Risk Reduction */}
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
            📈
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#16a34a',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            34%
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Risk Reduction
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#16a34a',
            fontWeight: '600'
          }}>
            +12% this month
          </div>
        </div>

        {/* MTTR */}
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
            MTTR
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#16a34a',
            fontWeight: '600'
          }}>
            -15% improvement
          </div>
        </div>

        {/* Policy Automation */}
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
            🤖
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#7c3aed',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            89%
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Policy Automation
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#7c3aed',
            fontWeight: '600'
          }}>
            24 active policies
          </div>
        </div>

        {/* Correlation Rate */}
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
            🔗
          </div>
          <div style={{
            fontSize: '3rem',
            fontWeight: 'bold',
            color: '#16a34a',
            marginBottom: '0.5rem',
            lineHeight: '1'
          }}>
            65%
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: '600',
            color: '#6b7280',
            textTransform: 'uppercase',
            letterSpacing: '0.1em'
          }}>
            Correlation Rate
          </div>
          <div style={{
            fontSize: '0.75rem',
            color: '#6b7280',
            fontWeight: '600'
          }}>
            noise reduction
          </div>
        </div>
      </div>

      {/* Charts Placeholder */}
      <div style={{
        backgroundColor: 'white',
        padding: '2.5rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        border: '1px solid #e5e7eb',
        textAlign: 'center',
        height: '300px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center'
      }}>
        <div style={{
          width: '80px',
          height: '80px',
          backgroundColor: '#f3f4f6',
          borderRadius: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '1.5rem',
          fontSize: '2.5rem'
        }}>
          📊
        </div>
        <h3 style={{
          fontSize: '1.5rem',
          fontWeight: '700',
          color: '#1f2937',
          marginBottom: '1rem'
        }}>
          Finding Trends (30 days)
        </h3>
        <p style={{
          fontSize: '1rem',
          color: '#6b7280',
          marginBottom: '1rem'
        }}>
          Chart visualization would be here
        </p>
        <p style={{
          fontSize: '0.875rem',
          color: '#9ca3af',
          fontStyle: 'italic'
        }}>
          Integration with Recharts for live data visualization
        </p>
      </div>
    </div>
  )
}

export default AnalyticsPage