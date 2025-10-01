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

      <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', background: 'white', padding: '1rem' }}>
        {loading ? (
          <div style={{ color: '#6b7280' }}>Loading…</div>
        ) : (
          <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'ui-monospace, monospace', color: '#111827' }}>{content}</pre>
        )}
      </div>
    </div>
  )
}

export default Docs
