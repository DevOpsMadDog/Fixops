import React, { useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import architectureDoc from '../content/architecture.md?raw'

function ArchitecturePage() {
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => {
      setContent(architectureDoc)
      setLoading(false)
    }, 500)

    return () => clearTimeout(timer)
  }, [])

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #0b1120 100%)',
      padding: '2rem'
    }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <div style={{
          textAlign: 'center',
          marginBottom: '2.5rem',
          color: 'white'
        }}>
          <h1 style={{
            fontSize: '3rem',
            fontWeight: '900',
            marginBottom: '1rem',
            background: 'linear-gradient(90deg, #38bdf8, #818cf8)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            🧠 Architecture Deep Dive
          </h1>
          <p style={{ fontSize: '1.2rem', color: '#e0f2fe' }}>
            Explore the Bayesian, Markov, and multi-LLM systems powering FixOps decisions
          </p>
        </div>

        <div style={{
          background: 'rgba(15, 23, 42, 0.9)',
          borderRadius: '20px',
          padding: '3rem',
          boxShadow: '0 30px 60px rgba(2, 6, 23, 0.45)',
          border: '1px solid rgba(129, 140, 248, 0.25)'
        }}>
          {loading ? (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '4rem',
              color: '#cbd5f5'
            }}>
              <div style={{
                width: '60px',
                height: '60px',
                border: '4px solid rgba(129, 140, 248, 0.2)',
                borderTop: '4px solid #60a5fa',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite',
                marginBottom: '1.5rem'
              }}></div>
              <p style={{ fontSize: '1.1rem', fontWeight: '500' }}>Loading architecture documentation...</p>
            </div>
          ) : (
            <div style={{
              fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
              lineHeight: '1.8',
              color: '#e2e8f0'
            }}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  h1: ({ children }) => <h1 style={{ fontSize: '2.4rem', fontWeight: '800', marginBottom: '1.5rem', color: '#93c5fd' }}>{children}</h1>,
                  h2: ({ children }) => <h2 style={{ fontSize: '1.8rem', fontWeight: '700', marginTop: '2.5rem', marginBottom: '1rem', color: '#bfdbfe' }}>{children}</h2>,
                  h3: ({ children }) => <h3 style={{ fontSize: '1.4rem', fontWeight: '600', marginTop: '2rem', marginBottom: '0.75rem', color: '#c4b5fd' }}>{children}</h3>,
                  code: ({ inline, children }) => inline
                    ? <code style={{ backgroundColor: 'rgba(15, 23, 42, 0.7)', padding: '0.2rem 0.4rem', borderRadius: '6px', fontSize: '0.9rem', fontFamily: '"JetBrains Mono", "Fira Code", monospace', border: '1px solid rgba(96, 165, 250, 0.3)', color: '#facc15' }}>{children}</code>
                    : <pre style={{ backgroundColor: 'rgba(15, 23, 42, 0.85)', padding: '1.5rem', borderRadius: '12px', overflow: 'auto', fontSize: '0.9rem', fontFamily: '"JetBrains Mono", "Fira Code", monospace', border: '1px solid rgba(96, 165, 250, 0.3)', boxShadow: '0 4px 12px rgba(15, 23, 42, 0.4)' }}><code>{children}</code></pre>
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}

export default ArchitecturePage
