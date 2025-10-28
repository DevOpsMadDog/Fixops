import React, { useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

function InstallPage() {
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchContent()
  }, [])

  const fetchContent = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/v1/docs/install')
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      const data = await response.text()
      setContent(data)
    } catch (error) {
      console.error('Failed to fetch install docs:', error)
      setContent('# Installation Guide\n\nError loading content. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const downloadContent = () => {
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'FixOps-Installation-Guide.md'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      padding: '2rem'
    }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
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
            🚀 Installation Guide
          </h1>
          <p style={{
            fontSize: '1.25rem',
            opacity: '0.9'
          }}>
            Complete setup instructions for FixOps enterprise deployment
          </p>
        </div>

        {/* Action Button */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          marginBottom: '2rem'
        }}>
          <button
            onClick={downloadContent}
            style={{
              padding: '0.75rem 1.5rem',
              borderRadius: '12px',
              border: 'none',
              background: 'linear-gradient(45deg, #2563eb, #1d4ed8)',
              color: 'white',
              fontWeight: '600',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)',
              transition: 'all 0.3s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            <span>📥</span> Download Guide
          </button>
        </div>

        {/* Content */}
        <div style={{
          background: 'white',
          borderRadius: '24px',
          padding: '3rem',
          minHeight: '600px',
          boxShadow: '0 25px 50px rgba(0,0,0,0.15)',
          border: '1px solid rgba(255,255,255,0.2)'
        }}>
          {loading ? (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '4rem',
              color: '#6b7280'
            }}>
              <div style={{
                width: '50px',
                height: '50px',
                border: '4px solid #e5e7eb',
                borderTop: '4px solid #3b82f6',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite',
                marginBottom: '1rem'
              }}></div>
              <p style={{ fontSize: '1.1rem', fontWeight: '500' }}>Loading installation guide...</p>
            </div>
          ) : (
            <div style={{
              fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
              lineHeight: '1.7',
              color: '#1f2937'
            }}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  h1: ({ children }) => <h1 style={{ fontSize: '2.5rem', fontWeight: '900', marginBottom: '1.5rem', background: 'linear-gradient(45deg, #1f2937, #4338ca)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', paddingBottom: '0.75rem', borderBottom: '3px solid #e5e7eb' }}>{children}</h1>,
                  h2: ({ children }) => <h2 style={{ fontSize: '2rem', fontWeight: '800', marginTop: '2.5rem', marginBottom: '1rem', color: '#1f2937' }}>{children}</h2>,
                  h3: ({ children }) => <h3 style={{ fontSize: '1.5rem', fontWeight: '700', marginTop: '2rem', marginBottom: '0.75rem', color: '#374151' }}>{children}</h3>,
                  code: ({ inline, children }) => inline 
                    ? <code style={{ backgroundColor: '#f1f5f9', padding: '0.2rem 0.4rem', borderRadius: '6px', fontSize: '0.9rem', fontFamily: '"JetBrains Mono", "Fira Code", monospace', border: '1px solid #e2e8f0', color: '#e11d48' }}>{children}</code>
                    : <pre style={{ backgroundColor: '#f8fafc', padding: '1.5rem', borderRadius: '12px', overflow: 'auto', fontSize: '0.9rem', fontFamily: '"JetBrains Mono", "Fira Code", monospace', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px rgba(0,0,0,0.05)' }}><code>{children}</code></pre>
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          )}
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

export default InstallPage
