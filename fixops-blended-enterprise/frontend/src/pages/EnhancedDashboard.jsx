import React, { useState, useEffect, useMemo } from 'react'
import { apiMethods } from '../utils/api'
import Tooltip from '../components/Tooltip'

function EnhancedDashboard() {
  const [enhancedMetrics, setEnhancedMetrics] = useState(null)
  const [llmComparison, setLlmComparison] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selectedService, setSelectedService] = useState('payment-processor')

  // Input state (Paste JSON only – upload UI removed per request)
  const [jsonInput, setJsonInput] = useState('{\n  "security_findings": [\n    {\n      "severity": "high",\n      "category": "injection",\n      "title": "SQL injection vulnerability in payment endpoint",\n      "source": "sonarqube"\n    }\n  ],\n  "business_context": {\n    "business_criticality": "critical",\n    "data_classification": "pii_financial"\n  }\n}')
  const [rawResponse, setRawResponse] = useState(null)
  const [statusMsg, setStatusMsg] = useState('idle')

  useEffect(() => {
    fetchEnhancedData()
  }, [])

  const fetchEnhancedData = async () => {
    try {
      const [capabilitiesRes, comparisonRes] = await Promise.all([
        apiMethods.enhanced.capabilities(),
        apiMethods.enhanced.compare({
          service_name: selectedService,
          security_findings: [
            { severity: 'high', category: 'injection', title: 'SQL injection vulnerability in payment endpoint', source: 'sonarqube' },
          ],
          business_context: { business_criticality: 'critical', data_classification: 'pii_financial' },
        }),
      ])
      setEnhancedMetrics(capabilitiesRes.data || {})
      setLlmComparison(comparisonRes.data?.data || {})
    } catch (error) {
      console.error('Failed to fetch enhanced data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getLLMIcon = (provider) => {
    const icons = { emergent_gpt5: '🧠', openai_gpt4: '🤖', anthropic_claude: '🧮', google_gemini: '💎', specialized_cyber: '🛡️' }
    return icons[provider] || '🤖'
  }

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.85) return '#16a34a'
    if (confidence >= 0.7) return '#d97706'
    return '#dc2626'
  }

  const handleAnalyze = async () => {
    try {
      setStatusMsg('processing')
      const parsed = JSON.parse(jsonInput || '{}')
      const payload = {
        service_name: selectedService,
        security_findings: parsed.security_findings || [],
        business_context: parsed.business_context || {},
      }
      const res = await apiMethods.enhanced.compare(payload)
      setRawResponse(res.data)
      setLlmComparison(res.data?.data || {})
      setStatusMsg('done')
    } catch (e) {
      console.error(e)
      setStatusMsg('error')
    }
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px', fontSize: '1.5rem', color: '#6b7280' }}>
        Loading Enhanced Multi-LLM Analysis...
      </div>
    )
  }

  // Steps explanation content + tooltip texts
  const steps = [
    { title: '1) Ingest Scans', emoji: '📥', text: 'Accept SARIF, SBOM, DAST, IaC, CSV and JSON outputs from existing scanners.', tip: 'Use API /api/v1/scans/upload or CLI in CI/CD. Chunked upload supported for large files.' },
    { title: '2) Normalize & De-duplicate', emoji: '🧹', text: 'Unify formats, normalize severities, and merge duplicates across tools.', tip: 'We canonicalize severities (low/medium/high/critical) and dedupe by rule_id + location + service.' },
    { title: '3) Business Context Enrichment', emoji: '🏢', text: 'Apply service criticality, data classification, internet exposure, owners, and SLAs.', tip: 'Business metadata amplifies risk so critical services and sensitive data weigh more in decisions.' },
    { title: '4) MITRE ATT&CK Mapping', emoji: '🎯', text: 'Map findings to TTPs to estimate attacker paths and business impact.', tip: 'IDs like T1190 are mapped to techniques. We compute attack-path severity based on combinations.' },
    { title: '5) Multi-LLM Analysis', emoji: '🧠', text: 'Consult GPT-4, Claude, Gemini, and specialized cyber models for layered insights.', tip: 'Models are orchestrated in parallel; we capture confidence, reasoning, and technique references.' },
    { title: '6) Consensus & Confidence', emoji: '📊', text: 'Weight model outputs, compute consensus verdict and confidence with disagreement analysis.', tip: 'Weighted consensus across models + variance check. High variance may trigger expert validation.' },
    { title: '7) Policy & Compliance', emoji: '⚖️', text: 'Evaluate OPA/Rego and frameworks (PCI, SOX, HIPAA, NIST) for governance alignment.', tip: 'Policies can override with block/allow conditions based on environment, data class, and severity.' },
    { title: '8) Decision', emoji: '🚦', text: 'Return ALLOW/BLOCK/DEFER with rationale and remediation recommendations.', tip: 'Decision includes rationale, evidence id, and recommended next steps for developers.' },
    { title: '9) Evidence Lake', emoji: '🗄️', text: 'Persist full evidence trail for audits, forensics, and reproducibility.', tip: 'We store consensus details and LLM reasoning snippets with traceable evidence IDs.' },
    { title: '10) Feedback & Learning', emoji: '🔁', text: 'Capture human validation to improve future decisions and reduce noise.', tip: 'Expert overrides and approvals are captured to tune future weighting/thresholds.' },
    { title: '11) Marketplace', emoji: '🛒', text: 'Leverage community policies, test sets, and patterns to accelerate adoption.', tip: 'Consume and contribute rules, controls, threat patterns, and attack graphs.' },
    { title: '12) CI/CD Integration', emoji: '⚙️', text: 'Use CLI in pipelines to gate deploys and export decisions to your tools.', tip: 'Exit codes used for gating: 0 allow, 1 block, 2 error. Artifacts can be saved for audit.' },
  ]

  return (
    <div style={{ padding: '2rem', maxWidth: '1600px', margin: '0 auto', backgroundColor: '#f8fafc', minHeight: '100vh' }}>
      {/* Input Panel (Paste JSON only) */}
      <div style={{ backgroundColor: 'white', padding: '1.5rem', borderRadius: '12px', border: '1px solid #e5e7eb', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#111827', marginBottom: '1rem' }}>
          Provide Security Findings
        </h2>
        <div>
          <label style={{ fontSize: '0.875rem', color: '#374151', fontWeight: 600 }}>Paste JSON</label>
          <textarea
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            rows={12}
            style={{ width: '100%', padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.875rem', border: '1px solid #e5e7eb', borderRadius: '8px', backgroundColor: '#f9fafb' }}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button onClick={handleAnalyze} style={{ marginTop: '0.75rem', padding: '0.5rem 1rem', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontWeight: 700 }}>Analyze JSON</button>
            {statusMsg !== 'idle' && (
              <span style={{ marginTop: '0.75rem', fontSize: '0.875rem', color: '#6b7280' }}>Status: {statusMsg}</span>
            )}
          </div>
        </div>
      </div>

      {/* Header */}
      <div style={{ marginBottom: '2rem', textAlign: 'center' }}>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '0.5rem' }}>
          ✨ Enhanced Multi-LLM Intelligence
        </h1>
        <p style={{ color: '#6b7280', fontSize: '1.125rem', marginBottom: '1rem' }}>
          Advanced security decisions powered by GPT-4, Claude, Gemini, and specialized models
        </p>

        {/* Enhanced Capabilities Overview */}
        <div style={{ backgroundColor: 'white', padding: '1.5rem', borderRadius: '12px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)', border: '1px solid #e5e7eb', display: 'inline-block' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#2563eb' }}>{enhancedMetrics?.llm_providers_available || 0}</div>
              <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>LLM Models</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#16a34a' }}>{enhancedMetrics?.mitre_techniques_mapped || 0}</div>
              <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>MITRE Techniques</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#7c3aed' }}>95%+</div>
              <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Accuracy</div>
            </div>
          </div>
        </div>
      </div>

      {/* Available LLM Providers */}
      <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)', border: '1px solid #e5e7eb', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#1f2937', marginBottom: '1.5rem' }}>
          🤖 Available AI Models & Specializations
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
          {enhancedMetrics?.supported_llms && Object.entries(enhancedMetrics.supported_llms).map(([provider, description]) => (
            <div key={provider} style={{ padding: '1.5rem', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e5e7eb' }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                <span style={{ fontSize: '2rem', marginRight: '0.75rem' }}>{getLLMIcon(provider)}</span>
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>{provider.replace('_', ' ').toUpperCase()}</h3>
                  <div style={{ fontSize: '0.75rem', fontWeight: '600', color: enhancedMetrics.llm_providers?.includes(provider) ? '#16a34a' : '#dc2626', backgroundColor: enhancedMetrics.llm_providers?.includes(provider) ? '#dcfce7' : '#fecaca', padding: '0.25rem 0.5rem', borderRadius: '12px', display: 'inline-block' }}>
                    {enhancedMetrics.llm_providers?.includes(provider) ? '✅ ACTIVE' : '❌ INACTIVE'}
                  </div>
                </div>
              </div>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0, lineHeight: '1.4' }}>{description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* LLM Comparison Analysis */}
      {llmComparison && (
        <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)', border: '1px solid #e5e7eb', marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#1f2937', marginBottom: '1.5rem' }}>
            🔍 Multi-LLM Analysis Comparison
          </h2>

          <div style={{ backgroundColor: '#f0f9ff', padding: '1rem', borderRadius: '8px', border: '1px solid #bfdbfe', marginBottom: '2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                  Consensus Decision: {llmComparison.final_decision?.toUpperCase()}
                </h3>
                <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                  {llmComparison.models_compared} AI models analyzed • {llmComparison.findings_count} security findings
                </p>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '2rem', fontWeight: 'bold', color: getConfidenceColor(llmComparison.consensus_confidence), marginBottom: '0.25rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                  {Math.round(llmComparison.consensus_confidence * 100)}%
                  <Tooltip text="Consensus confidence is computed via weighted aggregation across LLM outputs with variance checks; higher variance lowers confidence." position="left">
                    <span style={{ fontSize: '1rem', cursor: 'help' }}>ℹ️</span>
                  </Tooltip>
                </div>
                <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Consensus Confidence</div>
              </div>
            </div>
          </div>

          {/* Individual LLM Analyses */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
            {llmComparison.individual_analyses?.map((analysis, idx) => (
              <div key={idx} style={{ padding: '1.5rem', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px solid #e5e7eb' }}>
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
                  <span style={{ fontSize: '1.5rem', marginRight: '0.75rem' }}>{getLLMIcon(analysis.provider)}</span>
                  <div>
                    <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>{analysis.provider_name}
                      <Tooltip text="Per-model recommendation and confidence before consensus. Use this to understand model-specific strengths." position="right">
                        <span style={{ marginLeft: '0.4rem', cursor: 'help' }}>ℹ️</span>
                      </Tooltip>
                    </h4>
                    <div style={{ fontSize: '0.75rem', fontWeight: '600', color: getConfidenceColor(analysis.confidence), backgroundColor: analysis.confidence >= 0.85 ? '#dcfce7' : analysis.confidence >= 0.7 ? '#fef3c7' : '#fecaca', padding: '0.25rem 0.5rem', borderRadius: '12px', display: 'inline-block' }}>
                      {Math.round(analysis.confidence * 100)}% CONFIDENCE
                    </div>
                  </div>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Risk Assessment</span>
                    <Tooltip text="Relative business and exploitability risk per model." position="top"><span style={{ cursor: 'help' }}>ℹ️</span></Tooltip>
                  </div>
                  <div style={{ fontSize: '0.875rem', fontWeight: '700', color: analysis.risk_assessment === 'critical' ? '#dc2626' : analysis.risk_assessment === 'high' ? '#d97706' : analysis.risk_assessment === 'medium' ? '#2563eb' : '#16a34a' }}>
                    {analysis.risk_assessment?.toUpperCase()}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Recommendation</span>
                    <Tooltip text="Per-model action: allow, block or defer." position="top"><span style={{ cursor: 'help' }}>ℹ️</span></Tooltip>
                  </div>
                  <div style={{ fontSize: '0.875rem', fontWeight: '700', color: analysis.recommended_action === 'allow' ? '#16a34a' : analysis.recommended_action === 'block' ? '#dc2626' : '#d97706' }}>
                    {analysis.recommended_action?.toUpperCase()}
                  </div>

                  <div style={{ marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Processing Time</span>
                    <Tooltip text="Per-model latency in ms (approximate)." position="top"><span style={{ marginLeft: '0.25rem', cursor: 'help' }}>ℹ️</span></Tooltip>
                    <span style={{ fontSize: '0.875rem', color: '#6b7280', marginLeft: '0.5rem' }}>{analysis.processing_time_ms?.toFixed(0) || 0}ms</span>
                  </div>
                </div>

                {/* MITRE Techniques */}
                {analysis.mitre_techniques && analysis.mitre_techniques.length > 0 && (
                  <div style={{ marginBottom: '1rem' }}>
                    <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      MITRE Techniques
                      <Tooltip text="Technique IDs mapped to ATT&CK. Use capabilities to explore details and business impact mapping." position="top"><span style={{ cursor: 'help' }}>ℹ️</span></Tooltip>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                      {analysis.mitre_techniques.map((technique) => (
                        <span key={technique} style={{ fontSize: '0.75rem', fontWeight: '600', color: '#7c3aed', backgroundColor: '#f3e8ff', padding: '0.25rem 0.5rem', borderRadius: '12px' }}>
                          {technique}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Reasoning */}
                <div style={{ backgroundColor: '#f9fafb', padding: '1rem', borderRadius: '8px', border: '1px solid #f3f4f6' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    Analysis Reasoning
                    <Tooltip text="Model’s concise rationale to support the recommendation. Full evidence is saved in the evidence lake." position="top"><span style={{ cursor: 'help' }}>ℹ️</span></Tooltip>
                  </div>
                  <p style={{ fontSize: '0.75rem', color: '#6b7280', margin: 0, lineHeight: '1.4' }}>{analysis.reasoning || 'No detailed reasoning provided'}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Disagreement Analysis */}
          {llmComparison.disagreement_analysis && (
            <div style={{ marginTop: '2rem', padding: '1.5rem', backgroundColor: '#fef3c7', borderRadius: '12px', border: '1px solid #fed7aa' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#92400e', marginBottom: '1rem' }}>⚠️ Model Disagreement Analysis</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                <div>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Confidence Variance</span>
                  <Tooltip text="Spread of model confidences; high variance signals lower aggregate certainty." position="top"><span style={{ marginLeft: '0.25rem', cursor: 'help' }}>ℹ️</span></Tooltip>
                  <div style={{ fontSize: '1rem', fontWeight: '700', color: '#92400e' }}>{Math.round(llmComparison.disagreement_analysis.confidence_variance * 100)}%</div>
                </div>
                <div>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Decision Split</span>
                  <Tooltip text="Whether models disagree on allow/block/defer, which may require expert validation." position="top"><span style={{ marginLeft: '0.25rem', cursor: 'help' }}>ℹ️</span></Tooltip>
                  <div style={{ fontSize: '1rem', fontWeight: '700', color: '#92400e' }}>{llmComparison.disagreement_analysis.decision_split ? 'YES' : 'NO'}</div>
                </div>
                <div>
                  <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Expert Review</span>
                  <Tooltip text="Triggered when disagreement or risk thresholds are exceeded." position="top"><span style={{ marginLeft: '0.25rem', cursor: 'help' }}>ℹ️</span></Tooltip>
                  <div style={{ fontSize: '1rem', fontWeight: '700', color: '#92400e' }}>{llmComparison.disagreement_analysis.expert_validation_needed ? 'REQUIRED' : 'OPTIONAL'}</div>
                </div>
              </div>

              {llmComparison.disagreement_analysis.areas_of_disagreement?.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>Areas of Disagreement</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {llmComparison.disagreement_analysis.areas_of_disagreement.map((area) => (
                      <span key={area} style={{ fontSize: '0.75rem', fontWeight: '600', color: '#92400e', backgroundColor: '#fed7aa', padding: '0.25rem 0.5rem', borderRadius: '12px' }}>
                        {area.replace('_', ' ').toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Raw JSON + Download */}
          <div style={{ marginTop: '1.5rem' }}>
            <button onClick={() => {
              if (!rawResponse) return
              const blob = new Blob([JSON.stringify(rawResponse, null, 2)], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = 'enhanced_analysis.json'
              a.click()
              URL.revokeObjectURL(url)
            }} disabled={!rawResponse} style={{ padding: '0.5rem 1rem', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontWeight: 700 }}>
              Download JSON
            </button>
            {rawResponse && (
              <pre style={{ marginTop: '0.75rem', backgroundColor: '#0b1020', color: '#d1d5db', padding: '1rem', borderRadius: '8px', overflowX: 'auto', maxHeight: '300px' }}>
                {JSON.stringify(rawResponse, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* How FixOps Works - Step by Step (with tooltips) */}
      <div style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '16px', border: '1px solid #e5e7eb', boxShadow: '0 4px 6px rgba(0,0,0,0.06)', marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: '800', color: '#111827', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          🧭 How FixOps Works (Step‑by‑Step)
          <Tooltip text="End-to-end decision and verification pipeline from ingestion to deploy gate." position="right"><span style={{ cursor: 'help' }}>ℹ️</span></Tooltip>
        </h2>
        <p style={{ color: '#6b7280', marginBottom: '1rem' }}>
          FixOps is a Decision & Verification Engine. It enriches scanner output with business context and threat intelligence, then reaches a consensus decision with evidence and confidence.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
          {steps.map((s) => (
            <div key={s.title} style={{ padding: '1rem', border: '1px solid #f3f4f6', borderRadius: '12px', backgroundColor: '#f9fafb' }}>
              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '1.25rem' }}>{s.emoji}</span>
                <div style={{ fontWeight: 700, color: '#111827', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  {s.title}
                  <Tooltip text={s.tip}><span style={{ cursor: 'help' }}>ℹ️</span></Tooltip>
                </div>
              </div>
              <div style={{ fontSize: '0.9rem', color: '#4b5563', lineHeight: '1.5' }}>{s.text}</div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: '1rem', fontSize: '0.875rem', color: '#6b7280' }}>
          Need to ingest scans via CI/CD? Use the CLI to upload SARIF/JSON artifacts, then call the Enhanced Analysis API for decisions.
        </div>
      </div>

      {/* Enhanced Features */}
      <div style={{ background: 'linear-gradient(135deg, #1f2937 0%, #374151 100%)', padding: '2.5rem', borderRadius: '20px', color: 'white', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)' }}>
        <h2 style={{ fontSize: '2rem', fontWeight: '800', marginBottom: '1rem', textAlign: 'center' }}>🚀 Enhanced Intelligence Capabilities</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '2rem', marginBottom: '2rem' }}>
          <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', padding: '1.5rem', borderRadius: '12px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🧠</div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '0.5rem' }}>Multi-LLM Consensus</h3>
            <p style={{ fontSize: '0.875rem', opacity: 0.8 }}>GPT-4 + Claude + Gemini + Specialized models for highest accuracy</p>
          </div>
          <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', padding: '1.5rem', borderRadius: '12px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🎯</div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '0.5rem' }}>MITRE ATT&CK Mapping</h3>
            <p style={{ fontSize: '0.875rem', opacity: 0.8 }}>Vulnerability to attack technique correlation with business impact</p>
          </div>
          <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', padding: '1.5rem', borderRadius: '12px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📋</div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '0.5rem' }}>Compliance Automation</h3>
            <p style={{ fontSize: '0.875rem', opacity: 0.8 }}>PCI DSS, SOX, HIPAA, NIST framework validation</p>
          </div>
          <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', padding: '1.5rem', borderRadius: '12px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🛒</div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '0.5rem' }}>Marketplace Intelligence</h3>
            <p style={{ fontSize: '0.875rem', opacity: 0.8 }}>Community security patterns and expert knowledge</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default EnhancedDashboard
