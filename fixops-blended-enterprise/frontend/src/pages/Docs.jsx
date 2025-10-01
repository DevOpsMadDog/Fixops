import React, { useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const tabs = [
  { key: 'install', label: '🚀 Install', icon: '🚀', color: 'blue' },
  { key: 'ssvc', label: '🎯 SSVC', icon: '🎯', color: 'green' },
  { key: 'architecture', label: '🏗️ Architecture', icon: '🏗️', color: 'purple' },
  { key: 'requirements', label: '📋 Requirements', icon: '📋', color: 'orange' },
  { key: 'roadmap', label: '🗺️ Roadmap', icon: '🗺️', color: 'pink' },
]

const LS_LAST_TAB = 'fixops.docs.lastTab'

function Docs() {
  const [active, setActive] = useState(localStorage.getItem(LS_LAST_TAB) || 'install')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchDoc(active)
  }, [active])

  const fetchDoc = async (key) => {
    try {
      setLoading(true)
      const res = await fetch(`/api/v1/docs/${key}`)
      const txt = await res.text()
      setContent(txt)
      localStorage.setItem(LS_LAST_TAB, key)
    } catch (e) {
      setContent(`# Error\nUnable to load ${key} document.`)
    } finally {
      setLoading(false)
    }
  }

  const download = () => {
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${active.toUpperCase()}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  const [copySuccess, setCopySuccess] = useState(false)

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(`${window.location.origin}/api/v1/docs/${active}`)
      setCopySuccess(true)
      setTimeout(() => setCopySuccess(false), 2000)
    } catch (e) {
      console.error('Copy failed:', e)
    }
  }

  const getTabColors = (tab) => {
    const colors = {
      blue: { bg: '#dbeafe', border: '#3b82f6', text: '#1d4ed8' },
      green: { bg: '#d1fae5', border: '#10b981', text: '#047857' },
      purple: { bg: '#e9d5ff', border: '#8b5cf6', text: '#7c3aed' },
      orange: { bg: '#fed7aa', border: '#f97316', text: '#ea580c' },
      pink: { bg: '#fce7f3', border: '#ec4899', text: '#db2777' }
    }
    return colors[tab.color] || colors.blue
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
            📚 FixOps Documentation
          </h1>
          <p style={{ 
            fontSize: '1.25rem', 
            opacity: '0.9',
            marginBottom: '2rem'
          }}>
            Complete guide to enterprise DevSecOps decision engine
          </p>
        </div>

        {/* Navigation Tabs */}
        <div style={{ 
          display: 'flex', 
          gap: '1rem', 
          marginBottom: '2rem', 
          flexWrap: 'wrap',
          justifyContent: 'center'
        }}>
          {tabs.map(t => {
            const colors = getTabColors(t)
            const isActive = active === t.key
            return (
              <button 
                key={t.key} 
                onClick={() => setActive(t.key)} 
                style={{ 
                  padding: '1rem 1.5rem',
                  borderRadius: '16px',
                  border: `2px solid ${isActive ? colors.border : 'transparent'}`,
                  background: isActive ? colors.bg : 'rgba(255,255,255,0.9)',
                  color: isActive ? colors.text : '#374151',
                  fontWeight: '700',
                  fontSize: '1rem',
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                  boxShadow: isActive 
                    ? `0 8px 25px rgba(0,0,0,0.15), 0 0 0 1px ${colors.border}` 
                    : '0 4px 12px rgba(0,0,0,0.1)',
                  transform: isActive ? 'translateY(-2px)' : 'translateY(0)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.target.style.transform = 'translateY(-1px)'
                    e.target.style.boxShadow = '0 6px 16px rgba(0,0,0,0.15)'
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.target.style.transform = 'translateY(0)'
                    e.target.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)'
                  }
                }}
              >
                <span style={{ fontSize: '1.2rem' }}>{t.icon}</span>
                {t.label.replace(/^[^\s]+ /, '')}
              </button>
            )
          })}
        </div>

        {/* Action Buttons */}
        <div style={{ 
          display: 'flex', 
          gap: '1rem', 
          justifyContent: 'center',
          marginBottom: '2rem'
        }}>
          <button 
            onClick={download} 
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
            onMouseEnter={(e) => {
              e.target.style.transform = 'translateY(-2px)'
              e.target.style.boxShadow = '0 6px 16px rgba(37, 99, 235, 0.4)'
            }}
            onMouseLeave={(e) => {
              e.target.style.transform = 'translateY(0)'
              e.target.style.boxShadow = '0 4px 12px rgba(37, 99, 235, 0.3)'
            }}
          >
            <span>📥</span> Download .md
          </button>
          
          <button 
            onClick={copyLink} 
            style={{ 
              padding: '0.75rem 1.5rem',
              borderRadius: '12px',
              border: 'none',
              background: copySuccess 
                ? 'linear-gradient(45deg, #10b981, #047857)' 
                : 'linear-gradient(45deg, #6b7280, #4b5563)',
              color: 'white',
              fontWeight: '600',
              cursor: 'pointer',
              boxShadow: copySuccess 
                ? '0 4px 12px rgba(16, 185, 129, 0.3)'
                : '0 4px 12px rgba(107, 114, 128, 0.3)',
              transition: 'all 0.3s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
            onMouseEnter={(e) => {
              if (!copySuccess) {
                e.target.style.transform = 'translateY(-2px)'
                e.target.style.boxShadow = '0 6px 16px rgba(107, 114, 128, 0.4)'
              }
            }}
            onMouseLeave={(e) => {
              if (!copySuccess) {
                e.target.style.transform = 'translateY(0)'
                e.target.style.boxShadow = '0 4px 12px rgba(107, 114, 128, 0.3)'
              }
            }}
          >
            <span>{copySuccess ? '✅' : '🔗'}</span> 
            {copySuccess ? 'Copied!' : 'Copy Link'}
          </button>
        </div>

        {/* Content Container */}
        <div style={{ 
          background: 'white',
          borderRadius: '24px',
          padding: '3rem',
          minHeight: '600px',
          boxShadow: '0 25px 50px rgba(0,0,0,0.15)',
          border: '1px solid rgba(255,255,255,0.2)',
          backdropFilter: 'blur(10px)'
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
              <p style={{ fontSize: '1.1rem', fontWeight: '500' }}>Loading documentation...</p>
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
                  h1: ({ children }) => <h1 style={{ 
                    fontSize: '2.5rem', 
                    fontWeight: '900', 
                    marginBottom: '1.5rem', 
                    background: 'linear-gradient(45deg, #1f2937, #4338ca)',
                    WebkitBackgroundClip: 'text',
                    WebkitTextFillColor: 'transparent',
                    paddingBottom: '0.75rem',
                    borderBottom: '3px solid #e5e7eb'
                  }}>{children}</h1>,
                  h2: ({ children }) => <h2 style={{ 
                    fontSize: '2rem', 
                    fontWeight: '800', 
                    marginTop: '2.5rem', 
                    marginBottom: '1rem', 
                    color: '#1f2937',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}>{children}</h2>,
                  h3: ({ children }) => <h3 style={{ 
                    fontSize: '1.5rem', 
                    fontWeight: '700', 
                    marginTop: '2rem', 
                    marginBottom: '0.75rem', 
                    color: '#374151'
                  }}>{children}</h3>,
                  h4: ({ children }) => <h4 style={{ 
                    fontSize: '1.25rem', 
                    fontWeight: '600', 
                    marginTop: '1.5rem', 
                    marginBottom: '0.5rem', 
                    color: '#4b5563'
                  }}>{children}</h4>,
                  p: ({ children }) => <p style={{ 
                    marginBottom: '1.25rem', 
                    lineHeight: '1.8',
                    fontSize: '1.05rem'
                  }}>{children}</p>,
                  ul: ({ children }) => <ul style={{ 
                    marginBottom: '1.5rem', 
                    paddingLeft: '2rem'
                  }}>{children}</ul>,
                  ol: ({ children }) => <ol style={{ 
                    marginBottom: '1.5rem', 
                    paddingLeft: '2rem'
                  }}>{children}</ol>,
                  li: ({ children }) => <li style={{ 
                    marginBottom: '0.5rem',
                    lineHeight: '1.7'
                  }}>{children}</li>,
                  code: ({ inline, children }) => inline 
                    ? <code style={{ 
                        backgroundColor: '#f1f5f9', 
                        padding: '0.2rem 0.4rem', 
                        borderRadius: '6px', 
                        fontSize: '0.9rem', 
                        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                        border: '1px solid #e2e8f0',
                        color: '#e11d48'
                      }}>{children}</code>
                    : <pre style={{ 
                        backgroundColor: '#f8fafc', 
                        padding: '1.5rem', 
                        borderRadius: '12px', 
                        overflow: 'auto', 
                        fontSize: '0.9rem', 
                        fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                        border: '1px solid #e2e8f0',
                        boxShadow: '0 4px 6px rgba(0,0,0,0.05)'
                      }}><code>{children}</code></pre>,
                  table: ({ children }) => <div style={{ 
                    overflowX: 'auto',
                    marginBottom: '2rem',
                    borderRadius: '12px',
                    boxShadow: '0 4px 6px rgba(0,0,0,0.05)'
                  }}>
                    <table style={{ 
                      width: '100%', 
                      borderCollapse: 'collapse',
                      background: 'white'
                    }}>{children}</table>
                  </div>,
                  th: ({ children }) => <th style={{ 
                    border: '1px solid #e5e7eb', 
                    padding: '1rem', 
                    backgroundColor: '#f8fafc', 
                    fontWeight: '700', 
                    textAlign: 'left',
                    color: '#374151'
                  }}>{children}</th>,
                  td: ({ children }) => <td style={{ 
                    border: '1px solid #e5e7eb', 
                    padding: '1rem',
                    color: '#4b5563'
                  }}>{children}</td>,
                  blockquote: ({ children }) => <blockquote style={{ 
                    borderLeft: '4px solid #3b82f6', 
                    paddingLeft: '1.5rem', 
                    margin: '1.5rem 0', 
                    fontStyle: 'italic', 
                    color: '#6b7280',
                    backgroundColor: '#f8fafc',
                    padding: '1rem 1rem 1rem 1.5rem',
                    borderRadius: '0 8px 8px 0'
                  }}>{children}</blockquote>,
                  a: ({ href, children }) => <a 
                    href={href} 
                    style={{ 
                      color: '#3b82f6', 
                      textDecoration: 'none',
                      borderBottom: '1px solid #3b82f6',
                      transition: 'all 0.2s ease'
                    }} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    onMouseEnter={(e) => {
                      e.target.style.color = '#1d4ed8'
                      e.target.style.borderBottomColor = '#1d4ed8'
                    }}
                    onMouseLeave={(e) => {
                      e.target.style.color = '#3b82f6'
                      e.target.style.borderBottomColor = '#3b82f6'
                    }}
                  >{children}</a>
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          )}
        </div>
      </div>
      
      {/* CSS Animation for loading spinner */}
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

export default Docs
