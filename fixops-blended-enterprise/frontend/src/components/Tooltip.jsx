import React, { useState } from 'react'

function Tooltip({ text, children, position = 'top' }) {
  const [visible, setVisible] = useState(false)

  const positions = {
    top: { bottom: '125%', left: '50%', transform: 'translateX(-50%)' },
    right: { top: '50%', left: '105%', transform: 'translateY(-50%)' },
    bottom: { top: '125%', left: '50%', transform: 'translateX(-50%)' },
    left: { top: '50%', right: '105%', transform: 'translateY(-50%)' },
  }

  return (
    <span
      style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      {visible && (
        <span
          style={{
            position: 'absolute',
            zIndex: 50,
            backgroundColor: '#111827',
            color: 'white',
            padding: '0.5rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            minWidth: '220px',
            boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.1)',
            ...positions[position],
          }}
        >
          {text}
        </span>
      )}
    </span>
  )
}

export default Tooltip
