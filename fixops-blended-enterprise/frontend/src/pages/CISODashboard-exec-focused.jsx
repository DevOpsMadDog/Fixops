import React, { useState } from 'react'

function CISODashboard() {
  const [timeframe, setTimeframe] = useState('7d')
  
  // Executive decision summary data
  const decisionSummary = {
    '7d': {
      total_decisions: 67,
      allow_decisions: 52,
      block_decisions: 8, 
      defer_decisions: 7,
      avg_confidence: 89,
      critical_blocks: 3,
      compliance_rate: 94,
      risk_reduction: 23
    }
  }
  
  const currentSummary = decisionSummary[timeframe]
  
  const riskAreas = [
    {
      service: 'Payment Processing',
      risk_level: 'CRITICAL',
      decisions_blocked: 3,
      business_impact: 'Financial transactions',
      last_incident: '4h ago',
      compliance_status: 'PCI DSS Review Required'
    },
    {
      service: 'User Authentication', 
      risk_level: 'HIGH',
      decisions_blocked: 2,
      business_impact: 'User access security',
      last_incident: '12h ago',
      compliance_status: 'SOC2 Compliant'
    },
    {
      service: 'API Gateway',
      risk_level: 'MEDIUM',
      decisions_blocked: 1,
      business_impact: 'External integrations',
      last_incident: '2d ago', 
      compliance_status: 'NIST SSDF Compliant'
    }
  ]

  return (
    <div style={{
      padding: '2rem',
      maxWidth: '1600px',
      margin: '0 auto',
      backgroundColor: '#f8fafc',
      minHeight: '100vh'
    }}>
      
      {/* Executive Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{
          fontSize: '2.5rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.5rem'
        }}>
          Executive Security Risk Overview
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.125rem',
          marginBottom: '1.5rem'
        }}>
          Business-focused security decision intelligence and risk assessment
        </p>
        
        {/* Timeframe Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <label style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>
            Timeframe:
          </label>
          <select
            value={timeframe}
            onChange={(e) => setTimeframe(e.target.value)}
            style={{
              padding: '0.75rem 1rem',
              fontSize: '1rem',
              border: '2px solid #e5e7eb',
              borderRadius: '8px',
              backgroundColor: 'white'
            }}
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>
        </div>
      </div>

      {/* Executive Decision Metrics */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '1.5rem',
        marginBottom: '2rem'
      }}>
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>
            {currentSummary.total_decisions}
          </div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
            Total Decisions
          </div>
          <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
            Pipeline gates
          </div>
        </div>
        
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>
            {currentSummary.allow_decisions}
          </div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
            Deployments Allowed
          </div>
          <div style={{ fontSize: '0.75rem', color: '#16a34a', marginTop: '0.25rem', fontWeight: '600' }}>
            {Math.round(currentSummary.allow_decisions / currentSummary.total_decisions * 100)}% success rate
          </div>
        </div>
        
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#dc2626', marginBottom: '0.5rem' }}>
            {currentSummary.block_decisions}
          </div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
            Deployments Blocked
          </div>
          <div style={{ fontSize: '0.75rem', color: '#dc2626', marginTop: '0.25rem', fontWeight: '600' }}>
            Security issues prevented
          </div>
        </div>
        
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          border: '1px solid #e5e7eb',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>
            {currentSummary.avg_confidence}%
          </div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
            Avg Confidence
          </div>
          <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>
            Decision reliability
          </div>
        </div>
      </div>

      {/* High-Risk Areas Requiring Attention */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        border: '1px solid #e5e7eb',
        marginBottom: '2rem'
      }}>
        <h2 style={{
          fontSize: '1.75rem',
          fontWeight: '700',
          color: '#1f2937',
          marginBottom: '2rem',
          borderBottom: '2px solid #f3f4f6',
          paddingBottom: '1rem'
        }}>
          🚨 High-Risk Services - Action Required
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {riskAreas.map((area, idx) => (
            <div key={idx} style={{
              padding: '1.5rem',
              backgroundColor: area.risk_level === 'CRITICAL' ? '#fef2f2' : area.risk_level === 'HIGH' ? '#fef3c7' : '#f0f9ff',
              borderRadius: '12px',
              border: area.risk_level === 'CRITICAL' ? '1px solid #fecaca' : area.risk_level === 'HIGH' ? '1px solid #fed7aa' : '1px solid #bfdbfe'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                      {area.service}
                    </h3>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: '700',
                      color: area.risk_level === 'CRITICAL' ? '#dc2626' : area.risk_level === 'HIGH' ? '#d97706' : '#2563eb',
                      backgroundColor: area.risk_level === 'CRITICAL' ? '#fecaca' : area.risk_level === 'HIGH' ? '#fef3c7' : '#dbeafe',
                      padding: '0.25rem 0.75rem',
                      borderRadius: '20px',
                      marginLeft: '1rem'
                    }}>
                      {area.risk_level}
                    </span>
                  </div>
                  
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Business Impact:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>
                        {area.business_impact}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Decisions Blocked:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#dc2626' }}>
                        {area.decisions_blocked} deployments
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Last Incident:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>
                        {area.last_incident}
                      </div>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Compliance:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: area.compliance_status.includes('Review') ? '#d97706' : '#16a34a' }}>
                        {area.compliance_status}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Business Value & ROI */}
      <div style={{
        background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)',
        padding: '2.5rem',
        borderRadius: '20px',
        border: '1px solid #4b5563',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
        color: 'white'
      }}>
        <div style={{ marginBottom: '2rem' }}>
          <h2 style={{ 
            fontSize: '2.25rem', 
            fontWeight: '800', 
            margin: '0 0 0.5rem 0'
          }}>
            📊 Business Impact & ROI
          </h2>
          <p style={{
            fontSize: '1.125rem',
            opacity: 0.8,
            margin: 0
          }}>
            Quantified security decision value for executive reporting
          </p>
        </div>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '2rem',
          marginBottom: '2rem'
        }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              {currentSummary.risk_reduction}%
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Risk Reduction</div>
            <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: '0.25rem' }}>vs baseline</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              ${((currentSummary.block_decisions * 850000) / 1000000).toFixed(1)}M
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Breach Cost Avoided</div>
            <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: '0.25rem' }}>estimated savings</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              2.4h
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Mean Time to Decision</div>
            <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: '0.25rem' }}>vs 24h manual</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
              {currentSummary.compliance_rate}%
            </div>
            <div style={{ fontSize: '0.875rem', opacity: 0.8, fontWeight: '600' }}>Compliance Rate</div>
            <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: '0.25rem' }}>NIST + SOC2</div>
          </div>
        </div>
        
        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          padding: '1.5rem',
          borderRadius: '12px',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(255, 255, 255, 0.2)'
        }}>
          <h4 style={{ fontSize: '1.125rem', fontWeight: '700', marginBottom: '0.75rem' }}>
            📋 Executive Summary
          </h4>
          <p style={{ fontSize: '1rem', margin: 0, lineHeight: '1.6', opacity: 0.9 }}>
            FixOps Decision Engine prevented <strong>{currentSummary.block_decisions} high-risk deployments</strong> with 
            <strong> {currentSummary.avg_confidence}% average confidence</strong>. Critical security issues in payment 
            processing and authentication systems were identified and blocked before production impact. 
            Automated decision-making reduced security review time from 24h to 2.4h average.
          </p>
        </div>
      </div>
    </div>
  )
}

export default CISODashboard