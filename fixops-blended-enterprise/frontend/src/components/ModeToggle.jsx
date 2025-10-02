import React, { useState, useEffect } from 'react'

function ModeToggle() {
  const [currentMode, setCurrentMode] = useState('demo')
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    fetchCurrentMode()
  }, [])

  const fetchCurrentMode = async () => {
    try {
      const response = await fetch('/api/v1/decisions/core-components')
      const data = await response.json()
      const mode = data.data?.system_info?.mode || 'demo'
      setCurrentMode(mode)
    } catch (error) {
      setCurrentMode('demo')
    }
  }

  const toggleMode = async () => {
    setSwitching(true)
    try {
      // In a real implementation, this would call an API to switch modes
      // For now, we'll just show what would happen
      const newMode = currentMode === 'demo' ? 'production' : 'demo'
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      setCurrentMode(newMode)
      
      // Reload the page to reflect mode change
      setTimeout(() => {
        window.location.reload()
      }, 500)
      
    } catch (error) {
      console.error('Mode toggle failed:', error)
    } finally {
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
        fontWeight: '500',
        fontFamily: '"Inter", sans-serif'
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
          transition: 'all 0.3s ease',
          fontFamily: '"Inter", sans-serif'
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
        color: '#64748b',
        fontFamily: '"Inter", sans-serif'
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