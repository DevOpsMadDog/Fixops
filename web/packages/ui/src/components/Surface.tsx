'use client'

import { ReactNode } from 'react'

interface SurfaceProps {
  children: ReactNode
  variant?: 'default' | 'elevated' | 'inset' | 'glass'
  padding?: 'none' | 'sm' | 'md' | 'lg'
  className?: string
  hover?: boolean
  onClick?: () => void
}

const variants = {
  default: `
    bg-white/[0.03] 
    backdrop-blur-xl 
    ring-1 ring-white/[0.08]
    shadow-[0_1px_0_rgba(255,255,255,0.04),0_8px_24px_rgba(0,0,0,0.25)]
  `,
  elevated: `
    bg-white/[0.04] 
    backdrop-blur-xl 
    ring-1 ring-white/[0.1]
    shadow-[0_1px_0_rgba(255,255,255,0.06),0_12px_32px_rgba(0,0,0,0.35)]
  `,
  inset: `
    bg-black/20 
    ring-1 ring-white/[0.05]
    shadow-[inset_0_1px_2px_rgba(0,0,0,0.2)]
  `,
  glass: `
    bg-gradient-to-b from-white/[0.08] to-white/[0.02]
    backdrop-blur-2xl 
    ring-1 ring-white/[0.12]
    shadow-[0_1px_0_rgba(255,255,255,0.08),0_16px_48px_rgba(0,0,0,0.4)]
  `,
}

const paddings = {
  none: '',
  sm: 'p-3',
  md: 'p-5',
  lg: 'p-6',
}

/**
 * Premium glass-morphism surface component for cards, panels, and containers.
 * Features subtle gradients, backdrop blur, and refined shadows.
 */
export function Surface({
  children,
  variant = 'default',
  padding = 'md',
  className = '',
  hover = false,
  onClick,
}: SurfaceProps) {
  const Component = onClick ? 'button' : 'div'
  
  return (
    <Component
      onClick={onClick}
      className={`
        rounded-2xl
        ${variants[variant]}
        ${paddings[padding]}
        transition-all duration-200 ease-out
        ${hover ? 'hover:bg-white/[0.06] hover:ring-white/[0.12] hover:shadow-[0_1px_0_rgba(255,255,255,0.08),0_16px_40px_rgba(0,0,0,0.35)] hover:-translate-y-0.5' : ''}
        ${onClick ? 'cursor-pointer active:scale-[0.99]' : ''}
        ${className}
      `}
    >
      {children}
    </Component>
  )
}

export default Surface
