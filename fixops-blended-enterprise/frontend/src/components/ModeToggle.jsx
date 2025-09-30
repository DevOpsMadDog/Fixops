import React, { useState } from 'react'

function ModeToggle({ currentMode, onModeChange }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '1rem',
      padding: '0.5rem 1rem',
      backgroundColor: currentMode === 'demo' ? '#fef3c7' : '#f0fdf4',
      borderRadius: '20px',
      border: currentMode === 'demo' ? '1px solid #fed7aa' : '1px solid #bbf7d0'
    }}>
      <div style={{
        width: '8px',
        height: '8px',
        backgroundColor: currentMode === 'demo' ? '#d97706' : '#16a34a',
        borderRadius: '50%',
        animation: 'pulse 2s infinite'
      }}></div>
      
      <span style={{
        fontSize: '0.875rem',
        fontWeight: '700',
        color: currentMode === 'demo' ? '#92400e' : '#166534'
      }}>
        {currentMode === 'demo' ? '🎭 DEMO MODE' : '🏭 PRODUCTION MODE'}
      </span>
      
      <button
        onClick={() => onModeChange(currentMode === 'demo' ? 'production' : 'demo')}
        style={{
          padding: '0.25rem 0.75rem',
          backgroundColor: 'white',
          border: '1px solid #d1d5db',
          borderRadius: '12px',
          fontSize: '0.75rem',
          fontWeight: '600',
          color: '#374151',
          cursor: 'pointer',
          transition: 'all 0.2s ease-in-out'
        }}
        onMouseEnter={(e) => {
          e.target.style.backgroundColor = '#f3f4f6'
          e.target.style.borderColor = '#9ca3af'
        }}
        onMouseLeave={(e) => {
          e.target.style.backgroundColor = 'white'
          e.target.style.borderColor = '#d1d5db'
        }}
      >
        Switch to {currentMode === 'demo' ? 'Production' : 'Demo'}
      </button>
      
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}

export default ModeToggle