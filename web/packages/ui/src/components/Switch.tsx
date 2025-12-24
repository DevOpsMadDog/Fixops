'use client'

import { useCallback } from 'react'

interface SwitchProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label?: string
  labelPosition?: 'left' | 'right'
  size?: 'sm' | 'md' | 'lg'
  disabled?: boolean
  className?: string
}

/**
 * Apple-like toggle switch with smooth animations and accessibility.
 * Features a glass-morphism track, subtle shadows, and focus states.
 */
export function Switch({
  checked,
  onChange,
  label,
  labelPosition = 'left',
  size = 'md',
  disabled = false,
  className = '',
}: SwitchProps) {
  const handleClick = useCallback(() => {
    if (!disabled) {
      onChange(!checked)
    }
  }, [checked, onChange, disabled])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      if (!disabled) {
        onChange(!checked)
      }
    }
  }, [checked, onChange, disabled])

  const sizes = {
    sm: { track: 'h-5 w-9', knob: 'h-3.5 w-3.5', translate: 'translate-x-4' },
    md: { track: 'h-6 w-11', knob: 'h-4.5 w-4.5', translate: 'translate-x-5' },
    lg: { track: 'h-7 w-14', knob: 'h-5.5 w-5.5', translate: 'translate-x-7' },
  }

  const { track, knob, translate } = sizes[size]

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      {label && labelPosition === 'left' && (
        <span className="text-[13px] font-medium text-slate-300 select-none">
          {label}
        </span>
      )}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        className={`
          relative inline-flex ${track} items-center rounded-full
          transition-all duration-200 ease-out
          focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/20 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0b1220]
          active:scale-[0.98]
          ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
          ${checked 
            ? 'bg-gradient-to-r from-[#6B5AED] to-[#8B7CF7] shadow-[0_0_12px_rgba(107,90,237,0.4),inset_0_1px_0_rgba(255,255,255,0.1)]' 
            : 'bg-slate-700/80 shadow-[inset_0_1px_2px_rgba(0,0,0,0.3),inset_0_0_0_1px_rgba(255,255,255,0.05)]'
          }
        `}
      >
        <span
          className={`
            inline-block ${knob} rounded-full bg-white
            shadow-[0_1px_3px_rgba(0,0,0,0.3),0_1px_2px_rgba(0,0,0,0.2),inset_0_1px_0_rgba(255,255,255,0.8)]
            transition-transform duration-200 ease-out
            ${checked ? translate : 'translate-x-1'}
          `}
        />
      </button>
      {label && labelPosition === 'right' && (
        <span className="text-[13px] font-medium text-slate-300 select-none">
          {label}
        </span>
      )}
    </div>
  )
}

export default Switch
