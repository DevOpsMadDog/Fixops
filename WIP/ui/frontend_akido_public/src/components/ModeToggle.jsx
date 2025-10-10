import React, { useEffect, useState } from 'react'

function ModeToggle() {
  const [currentMode, setCurrentMode] = useState('demo')
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    fetchCurrentMode()
  }, [])

  const fetchCurrentMode = async () => {
    try {
      const response = await fetch('/api/v1/system-mode/current')
      if (!response.ok) {
        throw new Error('Failed to load current mode')
      }
      const data = await response.json()
      const mode = data?.data?.current_mode || (data?.data?.demo_mode_enabled ? 'demo' : 'production')
      setCurrentMode(mode || 'demo')
    } catch (error) {
      console.error('Failed to fetch current mode:', error)
      setCurrentMode('demo')
    }
  }

  const toggleMode = async () => {
    if (switching) return

    const targetMode = currentMode === 'demo' ? 'production' : 'demo'
    setSwitching(true)

    try {
      const response = await fetch('/api/v1/system-mode/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_mode: targetMode })
      })

      const payload = await response.json().catch(() => ({}))

      if (!response.ok) {
        const detail = payload?.detail
        const missingRequirements = Array.isArray(detail?.missing_requirements)
          ? detail.missing_requirements
          : Array.isArray(payload?.missing_requirements)
            ? payload.missing_requirements
            : []

        if (missingRequirements.length > 0) {
          alert(`Cannot switch to production until the following are configured:\n${missingRequirements.join('\n')}`)
        } else {
          const message = typeof detail === 'string'
            ? detail
            : detail?.message || 'Unknown error occurred while toggling mode.'
          alert(`Mode toggle failed: ${message}`)
        }
        return
      }

      const missingRequirements = Array.isArray(payload?.missing_requirements) ? payload.missing_requirements : []
      if (missingRequirements.length > 0) {
        alert(`Mode toggle registered but additional setup is required:\n${missingRequirements.join('\n')}`)
      } else if (payload?.restart_required) {
        alert(`Mode toggle request sent. Set DEMO_MODE=${targetMode === 'demo' ? 'true' : 'false'} and restart the service to complete the switch.`)
      } else {
        alert(`Mode switched to ${targetMode.toUpperCase()}.`)
      }
    } catch (error) {
      console.error('Mode toggle failed:', error)
      alert('Mode toggle failed. Check console for details.')
    } finally {
      await fetchCurrentMode()
      setSwitching(false)
    }
  }

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem',
      padding: '0.5rem 1rem',
      backgroundColor: 'rgba(255, 255, 255, 0.1)',
      borderRadius: '20px',
      border: '1px solid rgba(255, 255, 255, 0.2)'
    }}>
      <div style={{
        fontSize: '0.75rem',
        color: '#94a3b8',
        fontWeight: '500'
      }}>
        MODE:
      </div>

      <button
        onClick={toggleMode}
        disabled={switching}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.375rem 0.75rem',
          backgroundColor: currentMode === 'demo' ? 'rgba(167, 139, 250, 0.2)' : 'rgba(16, 185, 129, 0.2)',
          border: `1px solid ${currentMode === 'demo' ? '#a78bfa' : '#10b981'}`,
          borderRadius: '15px',
          color: currentMode === 'demo' ? '#a78bfa' : '#10b981',
          fontSize: '0.75rem',
          fontWeight: '600',
          cursor: switching ? 'wait' : 'pointer',
          transition: 'all 0.3s ease'
        }}
      >
        {switching ? (
          <>
            <div style={{
              width: '12px',
              height: '12px',
              border: '2px solid transparent',
              borderTop: '2px solid currentColor',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite'
            }}></div>
            SWITCHING...
          </>
        ) : (
          <>
            <div style={{
              width: '6px',
              height: '6px',
              backgroundColor: 'currentColor',
              borderRadius: '50%'
            }}></div>
            {currentMode.toUpperCase()}
          </>
        )}
      </button>

      <div style={{
        fontSize: '0.625rem',
        color: '#64748b'
      }}>
        {currentMode === 'demo' ? 'Showcase' : 'Live'}
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

export default ModeToggle
