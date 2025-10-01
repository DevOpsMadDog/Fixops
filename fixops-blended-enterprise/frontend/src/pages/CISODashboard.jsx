import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { apiMethods } from '../utils/api'

function CISODashboard() {
  const [timeframe, setTimeframe] = useState('7d')

  // Executive decision summary data (static demo)
  const decisionSummary = {
    '7d': { total_decisions: 67, allow_decisions: 52, block_decisions: 8, defer_decisions: 7, avg_confidence: 89, critical_blocks: 3, compliance_rate: 94, risk_reduction: 23 }
  }
  const currentSummary = decisionSummary[timeframe]

  const riskAreas = [
    { service: 'Payment Processing', risk_level: 'CRITICAL', decisions_blocked: 3, business_impact: 'Financial transactions', last_incident: '4h ago', compliance_status: 'PCI DSS Review Required' },
    { service: 'User Authentication', risk_level: 'HIGH', decisions_blocked: 2, business_impact: 'User access security', last_incident: '12h ago', compliance_status: 'SOC2 Compliant' },
    { service: 'API Gateway', risk_level: 'MEDIUM', decisions_blocked: 1, business_impact: 'External integrations', last_incident: '2d ago', compliance_status: 'NIST SSDF Compliant' }
  ]

  // Compact Enhanced analysis snapshot
  const [snapshot, setSnapshot] = useState({ loading: true, error: null, data: null })

  useEffect(() => {
    const fetchSnapshot = async () => {
      try {
        const res = await apiMethods.enhanced.compare({
          service_name: 'payment-processor',
          security_findings: [ { severity: 'high', category: 'injection', title: 'SQL injection vulnerability in payment endpoint', source: 'sonarqube' } ],
          business_context: { business_criticality: 'critical', data_classification: 'pii_financial' },
        })
        setSnapshot({ loading: false, error: null, data: res.data?.data })
      } catch (e) {
        setSnapshot({ loading: false, error: e?.message || 'Failed to load', data: null })
      }
    }
    fetchSnapshot()
  }, [])

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.85) return '#16a34a'
    if (confidence >= 0.7) return '#d97706'
    return '#dc2626'
  }

  return (
    <div style={{ padding: '2rem', maxWidth: '1600px', margin: '0 auto', backgroundColor: '#f8fafc', minHeight: '100vh' }}>
      {/* Executive Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '0.5rem' }}>
          Executive Security Risk Overview
        </h1>
        <p style={{ color: '#6b7280', fontSize: '1.125rem', marginBottom: '1.5rem' }}>
          Business-focused security decision intelligence and risk assessment
        </p>

        {/* Timeframe Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <label style={{ fontSize: '1rem', fontWeight: '600', color: '#374151' }}>Timeframe:</label>
          <select value={timeframe} onChange={(e) => setTimeframe(e.target.value)} style={{ padding: '0.75rem 1rem', fontSize: '1rem', border: '2px solid #e5e7eb', borderRadius: '8px', backgroundColor: 'white' }}>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>
        </div>
      </div>

      {/* Executive Decision Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb', textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>{currentSummary.total_decisions}</div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Total Decisions</div>
          <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>Pipeline gates</div>
        </div>
        <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb', textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>{currentSummary.allow_decisions}</div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Deployments Allowed</div>
          <div style={{ fontSize: '0.75rem', color: '#16a34a', marginTop: '0.25rem', fontWeight: '600' }}>{Math.round(currentSummary.allow_decisions / currentSummary.total_decisions * 100)}% success rate</div>
        </div>
        <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb', textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#dc2626', marginBottom: '0.5rem' }}>{currentSummary.block_decisions}</div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Deployments Blocked</div>
          <div style={{ fontSize: '0.75rem', color: '#dc2626', marginTop: '0.25rem', fontWeight: '600' }}>Security issues prevented</div>
        </div>
        <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb', textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>{currentSummary.avg_confidence}%</div>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Avg Confidence</div>
          <div style={{ fontSize: '0.75rem', color: '#9ca3af', marginTop: '0.25rem' }}>Decision reliability</div>
        </div>
      </div>

      {/* Enhanced Analysis Snapshot (compact) */}
      <div style={{ backgroundColor: 'white', padding: '1.5rem', borderRadius: '16px', border: '1px solid #e5e7eb', boxShadow: '0 4px 6px rgba(0,0,0,0.05)', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#111827', margin: 0 }}>
            🔍 Enhanced Analysis Snapshot
          </h2>
          <Link to="/enhanced" style={{ textDecoration: 'none', padding: '0.5rem 0.75rem', borderRadius: '8px', backgroundColor: '#2563eb', color: 'white', fontWeight: 700 }}>
            View Full Analysis
          </Link>
        </div>

        <div style={{ marginTop: '0.75rem' }}>
          {snapshot.loading && (
            <div style={{ fontSize: '0.9rem', color: '#6b7280' }}>Loading snapshot…</div>
          )}
          {!snapshot.loading && snapshot.error && (
            <div style={{ fontSize: '0.9rem', color: '#dc2626' }}>Unavailable: {snapshot.error}</div>
          )}
          {!snapshot.loading && snapshot.data && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
              <div style={{ padding: '1rem', backgroundColor: '#f8fafc', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: 600 }}>Consensus Decision</div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: '#111827' }}>{snapshot.data.final_decision?.toUpperCase()}</div>
              </div>
              <div style={{ padding: '1rem', backgroundColor: '#f8fafc', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: 600 }}>Confidence</div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: getConfidenceColor(snapshot.data.consensus_confidence) }}>{Math.round(snapshot.data.consensus_confidence * 100)}%</div>
              </div>
              <div style={{ padding: '1rem', backgroundColor: '#f8fafc', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: 600 }}>Models Compared</div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: '#111827' }}>{snapshot.data.models_compared}</div>
              </div>
              <div style={{ padding: '1rem', backgroundColor: '#f8fafc', border: '1px solid #e5e7eb', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: 600 }}>Disagreement</div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: snapshot.data.disagreement_analysis?.decision_split ? '#d97706' : '#16a34a' }}>{snapshot.data.disagreement_analysis?.decision_split ? 'YES' : 'NO'}</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* High-Risk Areas Requiring Attention */}
      <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.75rem', fontWeight: '700', color: '#1f2937', marginBottom: '2rem', borderBottom: '2px solid #f3f4f6', paddingBottom: '1rem' }}>
          🚨 High-Risk Services - Action Required
        </h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {riskAreas.map((area, idx) => (
            <div key={idx} style={{ padding: '1.5rem', backgroundColor: area.risk_level === 'CRITICAL' ? '#fef2f2' : area.risk_level === 'HIGH' ? '#fef3c7' : '#f0f9ff', borderRadius: '12px', border: area.risk_level === 'CRITICAL' ? '1px solid #fecaca' : area.risk_level === 'HIGH' ? '1px solid #fed7aa' : '1px solid #bfdbfe' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>{area.service}</h3>
                    <span style={{ fontSize: '0.75rem', fontWeight: '700', color: area.risk_level === 'CRITICAL' ? '#dc2626' : area.risk_level === 'HIGH' ? '#d97706' : '#2563eb', backgroundColor: area.risk_level === 'CRITICAL' ? '#fecaca' : area.risk_level === 'HIGH' ? '#fef3c7' : '#dbeafe', padding: '0.25rem 0.75rem', borderRadius: '20px', marginLeft: '1rem' }}>{area.risk_level}</span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Business Impact:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>{area.business_impact}</div>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Decisions Blocked:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#dc2626' }}>{area.decisions_blocked} deployments</div>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Last Incident:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>{area.last_incident}</div>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Compliance:</span>
                      <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>{area.compliance_status}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default CISODashboard
