import React, { useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const tabs = [
  { key: 'install', label: 'Install' },
  { key: 'ssvc', label: 'SSVC' },
  { key: 'architecture', label: 'Architecture' },
  { key: 'requirements', label: 'Requirements' },
  { key: 'roadmap', label: 'Roadmap' },
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

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(`${window.location.origin}/api/v1/docs/${active}`)
      alert('Link copied')
    } catch (e) {
      alert('Copy failed')
    }
  }

  return (
    <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
      <h1 style={{ fontSize: '2rem', fontWeight: 800, marginBottom: '1rem' }}>Documentation</h1>
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        {tabs.map(t => (
          <button key={t.key} onClick={() => setActive(t.key)} style={{ padding: '0.5rem 0.75rem', borderRadius: '8px', border: '1px solid #e5e7eb', background: active === t.key ? '#111827' : 'white', color: active === t.key ? 'white' : '#111827', fontWeight: 700 }}>
            {t.label}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
          <button onClick={download} style={{ padding: '0.5rem 0.75rem', borderRadius: '8px', border: '1px solid #e5e7eb', background: '#2563eb', color: 'white', fontWeight: 700 }}>Download .md</button>
          <button onClick={copyLink} style={{ padding: '0.5rem 0.75rem', borderRadius: '8px', border: '1px solid #e5e7eb', background: '#10b981', color: 'white', fontWeight: 700 }}>Copy Link</button>
        </div>
      </div>

      <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', background: 'white', padding: '2rem', minHeight: '400px' }}>
        {loading ? (
          <div style={{ color: '#6b7280', textAlign: 'center', padding: '2rem' }}>Loading…</div>
        ) : (
          <div style={{ 
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
            lineHeight: '1.6',
            color: '#111827'
          }}>
            <ReactMarkdown 
              remarkPlugins={[remarkGfm]}
              components={{
                h1: ({ children }) => <h1 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '1rem', borderBottom: '2px solid #e5e7eb', paddingBottom: '0.5rem' }}>{children}</h1>,
                h2: ({ children }) => <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold', marginTop: '1.5rem', marginBottom: '0.75rem', color: '#1f2937' }}>{children}</h2>,
                h3: ({ children }) => <h3 style={{ fontSize: '1.25rem', fontWeight: 'semibold', marginTop: '1.25rem', marginBottom: '0.5rem', color: '#374151' }}>{children}</h3>,
                h4: ({ children }) => <h4 style={{ fontSize: '1.1rem', fontWeight: 'semibold', marginTop: '1rem', marginBottom: '0.5rem', color: '#4b5563' }}>{children}</h4>,
                p: ({ children }) => <p style={{ marginBottom: '1rem', lineHeight: '1.7' }}>{children}</p>,
                ul: ({ children }) => <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>{children}</ul>,
                ol: ({ children }) => <ol style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>{children}</ol>,
                li: ({ children }) => <li style={{ marginBottom: '0.25rem' }}>{children}</li>,
                code: ({ inline, children }) => inline 
                  ? <code style={{ backgroundColor: '#f3f4f6', padding: '0.125rem 0.25rem', borderRadius: '0.25rem', fontSize: '0.875rem', fontFamily: 'ui-monospace, monospace' }}>{children}</code>
                  : <pre style={{ backgroundColor: '#f8f9fa', padding: '1rem', borderRadius: '0.5rem', overflow: 'auto', fontSize: '0.875rem', fontFamily: 'ui-monospace, monospace' }}><code>{children}</code></pre>,
                table: ({ children }) => <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '1rem', border: '1px solid #e5e7eb' }}>{children}</table>,
                th: ({ children }) => <th style={{ border: '1px solid #e5e7eb', padding: '0.75rem', backgroundColor: '#f9fafb', fontWeight: 'semibold', textAlign: 'left' }}>{children}</th>,
                td: ({ children }) => <td style={{ border: '1px solid #e5e7eb', padding: '0.75rem' }}>{children}</td>,
                blockquote: ({ children }) => <blockquote style={{ borderLeft: '4px solid #e5e7eb', paddingLeft: '1rem', margin: '1rem 0', fontStyle: 'italic', color: '#6b7280' }}>{children}</blockquote>,
                a: ({ href, children }) => <a href={href} style={{ color: '#2563eb', textDecoration: 'underline' }} target="_blank" rel="noopener noreferrer">{children}</a>
              }}
            >
              {content}
            </ReactMarkdown>
          </div>
        )}
      </div>
    </div>
  )
}

export default Docs
