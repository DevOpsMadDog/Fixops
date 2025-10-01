import React, { useEffect, useState } from 'react'

function OssIntegrationsPage() {
  const [toolsStatus, setToolsStatus] = useState({})
  const [loading, setLoading] = useState(true)
  const [scanResults, setScanResults] = useState({})
  const [scanLoading, setScanLoading] = useState({})

  useEffect(() => {
    fetchToolsStatus()
  }, [])

  const fetchToolsStatus = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/v1/oss/status')
      const data = await response.json()
      setToolsStatus(data)
    } catch (error) {
      console.error('Failed to fetch tools status:', error)
    } finally {
      setLoading(false)
    }
  }

  const runScan = async (tool, target = "nginx:latest") => {
    try {
      setScanLoading(prev => ({ ...prev, [tool]: true }))
      let endpoint = `/api/v1/oss/scan/${tool}`
      
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type: "image" })
      })
      
      const results = await response.json()
      setScanResults(prev => ({ ...prev, [tool]: results }))
    } catch (error) {
      console.error(`${tool} scan failed:`, error)
      setScanResults(prev => ({ ...prev, [tool]: { status: 'error', error: error.message } }))
    } finally {
      setScanLoading(prev => ({ ...prev, [tool]: false }))
    }
  }

  const getToolCard = (toolName, toolData, description, capabilities) => {
    const isAvailable = toolData?.available
    const cardColor = isAvailable ? '#10b981' : '#ef4444'
    const bgGradient = isAvailable 
      ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
      : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)'

    return (
      <div style={{
        background: 'white',
        borderRadius: '16px',
        padding: '2rem',
        boxShadow: '0 10px 25px rgba(0,0,0,0.1)',
        border: `2px solid ${isAvailable ? '#10b981' : '#ef4444'}`,
        transition: 'all 0.3s ease'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
          marginBottom: '1.5rem'
        }}>
          <div style={{
            width: '60px',
            height: '60px',
            background: bgGradient,
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.5rem'
          }}>
            {getToolIcon(toolName)}
          </div>
          <div>
            <h3 style={{
              margin: 0,
              fontSize: '1.5rem',
              fontWeight: '700',
              color: '#1f2937'
            }}>
              {toolName.charAt(0).toUpperCase() + toolName.slice(1)}
            </h3>
            <p style={{
              margin: 0,
              color: isAvailable ? '#10b981' : '#ef4444',
              fontWeight: '600'
            }}>
              {isAvailable ? '✅ Available' : '❌ Not Installed'}
              {toolData?.version && ` (${toolData.version})`}
            </p>
          </div>
        </div>

        <p style={{
          color: '#6b7280',
          lineHeight: '1.6',
          marginBottom: '1.5rem'
        }}>
          {description}
        </p>

        <div style={{ marginBottom: '1.5rem' }}>
          <h4 style={{
            fontSize: '1rem',
            fontWeight: '600',
            color: '#374151',
            marginBottom: '0.5rem'
          }}>
            Capabilities:
          </h4>
          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '0.5rem'
          }}>
            {capabilities.map(cap => (
              <span key={cap} style={{
                background: '#f3f4f6',
                color: '#374151',
                padding: '0.25rem 0.75rem',
                borderRadius: '20px',
                fontSize: '0.875rem',
                fontWeight: '500'
              }}>
                {cap}
              </span>
            ))}
          </div>
        </div>

        {isAvailable && (toolName === 'trivy' || toolName === 'grype') && (
          <div>
            <button
              onClick={() => runScan(toolName)}
              disabled={scanLoading[toolName]}
              style={{
                background: scanLoading[toolName] 
                  ? '#6b7280' 
                  : 'linear-gradient(45deg, #3b82f6, #1d4ed8)',
                color: 'white',
                border: 'none',
                padding: '0.75rem 1.5rem',
                borderRadius: '8px',
                fontWeight: '600',
                cursor: scanLoading[toolName] ? 'not-allowed' : 'pointer',
                transition: 'all 0.3s ease',
                marginBottom: '1rem'
              }}
            >
              {scanLoading[toolName] ? '🔄 Scanning...' : '🔍 Test Scan'}
            </button>

            {scanResults[toolName] && (
              <div style={{
                background: '#f8fafc',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                padding: '1rem',
                marginTop: '1rem'
              }}>
                <h5 style={{
                  margin: '0 0 0.5rem 0',
                  fontWeight: '600',
                  color: '#374151'
                }}>
                  Scan Results:
                </h5>
                <pre style={{
                  fontSize: '0.75rem',
                  color: '#4b5563',
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  maxHeight: '200px',
                  overflow: 'auto'
                }}>
                  {JSON.stringify(scanResults[toolName], null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  const getToolIcon = (tool) => {
    const icons = {
      trivy: '🛡️',
      grype: '🔍',
      opa: '⚖️',
      sigstore: '🔒'
    }
    return icons[tool] || '🔧'
  }

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <div style={{
          background: 'white',
          borderRadius: '16px',
          padding: '2rem',
          textAlign: 'center',
          boxShadow: '0 25px 50px rgba(0,0,0,0.15)'
        }}>
          <div style={{
            width: '50px',
            height: '50px',
            border: '4px solid #e5e7eb',
            borderTop: '4px solid #3b82f6',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem'
          }}></div>
          <p>Loading OSS Tools Status...</p>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      padding: '2rem'
    }}>
      <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{
          textAlign: 'center',
          marginBottom: '3rem',
          color: 'white'
        }}>
          <h1 style={{
            fontSize: '3.5rem',
            fontWeight: '900',
            marginBottom: '1rem',
            textShadow: '2px 2px 4px rgba(0,0,0,0.3)',
            background: 'linear-gradient(45deg, #fff, #f0f9ff)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            🔧 OSS Tools Integration
          </h1>
          <p style={{
            fontSize: '1.25rem',
            opacity: '0.9',
            marginBottom: '1rem'
          }}>
            Integrated open source security tools for comprehensive scanning
          </p>
          {toolsStatus.summary && (
            <div style={{
              background: 'rgba(255,255,255,0.1)',
              borderRadius: '12px',
              padding: '1rem',
              backdropFilter: 'blur(10px)',
              display: 'inline-block'
            }}>
              <span style={{ fontSize: '1.1rem' }}>
                {toolsStatus.summary.available_tools}/{toolsStatus.summary.total_tools} Tools Available
              </span>
            </div>
          )}
        </div>

        {/* Tools Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
          gap: '2rem',
          marginBottom: '3rem'
        }}>
          {toolsStatus.tools && Object.entries(toolsStatus.tools).map(([toolName, toolData]) => {
            const descriptions = {
              trivy: "Container and filesystem vulnerability scanner with comprehensive CVE database",
              grype: "Fast vulnerability scanner for containers and filesystems with detailed reporting",
              opa: "General-purpose policy engine for cloud-native environments with Rego language",
              sigstore: "Keyless container signing and verification for supply chain security"
            }
            
            const capabilities = {
              trivy: ["Image Scanning", "SARIF Output", "CVE Detection", "License Scanning"],
              grype: ["Container Scanning", "SBOM Analysis", "Filesystem Scanning", "JSON Output"],
              opa: ["Policy Evaluation", "Rego Policies", "Decision Engine", "Compliance Checks"],
              sigstore: ["Keyless Signing", "Signature Verification", "Attestations", "Transparency Log"]
            }

            return getToolCard(
              toolName,
              toolData,
              descriptions[toolName],
              capabilities[toolName]
            )
          })}
        </div>

        {/* Installation Guide */}
        <div style={{
          background: 'white',
          borderRadius: '24px',
          padding: '3rem',
          boxShadow: '0 25px 50px rgba(0,0,0,0.15)',
          marginTop: '2rem'
        }}>
          <h2 style={{
            fontSize: '2rem',
            fontWeight: '800',
            marginBottom: '1.5rem',
            color: '#1f2937',
            textAlign: 'center'
          }}>
            🚀 Quick Installation Guide
          </h2>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '1.5rem'
          }}>
            <div style={{
              background: '#f8fafc',
              borderRadius: '12px',
              padding: '1.5rem',
              border: '1px solid #e2e8f0'
            }}>
              <h3 style={{ color: '#1f2937', marginBottom: '1rem' }}>🛡️ Install Trivy</h3>
              <pre style={{
                background: '#1f2937',
                color: '#f1f5f9',
                padding: '1rem',
                borderRadius: '8px',
                overflow: 'auto',
                fontSize: '0.875rem'
              }}>
{`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`}
              </pre>
            </div>

            <div style={{
              background: '#f8fafc',
              borderRadius: '12px',
              padding: '1.5rem',
              border: '1px solid #e2e8f0'
            }}>
              <h3 style={{ color: '#1f2937', marginBottom: '1rem' }}>🔍 Install Grype</h3>
              <pre style={{
                background: '#1f2937',
                color: '#f1f5f9',
                padding: '1rem',
                borderRadius: '8px',
                overflow: 'auto',
                fontSize: '0.875rem'
              }}>
{`curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`}
              </pre>
            </div>

            <div style={{
              background: '#f8fafc',
              borderRadius: '12px',
              padding: '1.5rem',
              border: '1px solid #e2e8f0'
            }}>
              <h3 style={{ color: '#1f2937', marginBottom: '1rem' }}>⚖️ Install OPA</h3>
              <pre style={{
                background: '#1f2937',
                color: '#f1f5f9',
                padding: '1rem',
                borderRadius: '8px',
                overflow: 'auto',
                fontSize: '0.875rem'
              }}>
{`curl -L -o opa https://openpolicyagent.org/downloads/v0.57.0/opa_linux_amd64_static
chmod 755 ./opa && sudo mv opa /usr/local/bin`}
              </pre>
            </div>

            <div style={{
              background: '#f8fafc',
              borderRadius: '12px',
              padding: '1.5rem',
              border: '1px solid #e2e8f0'
            }}>
              <h3 style={{ color: '#1f2937', marginBottom: '1rem' }}>🔒 Install Cosign</h3>
              <pre style={{
                background: '#1f2937',
                color: '#f1f5f9',
                padding: '1rem',
                borderRadius: '8px',
                overflow: 'auto',
                fontSize: '0.875rem'
              }}>
{`curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign`}
              </pre>
            </div>
          </div>
        </div>
      </div>

      <style dangerouslySetInnerHTML={{
        __html: `
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `
      }} />
    </div>
  )
}

export default OssIntegrationsPage