import React, { useState } from 'react'

function ModeToggle() {
  const [currentMode, setCurrentMode] = useState('demo')
  const [switching, setSwitching] = useState(false)

  const toggleMode = () => {
    if (switching) return

    setSwitching(true)
    const nextMode = currentMode === 'demo' ? 'production' : 'demo'

    setTimeout(() => {
      setCurrentMode(nextMode)
      alert(`Mode switched to ${nextMode.toUpperCase()} (simulation).\n\nConfigure DEMO_MODE=${nextMode === 'demo' ? 'true' : 'false'} in a real deployment.`)
      setSwitching(false)
    }, 500)
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
