'use client'

import { Loader2 } from 'lucide-react'

type StatusType = 'loading' | 'error' | 'warning' | 'success' | 'info' | 'demo' | 'live'

interface StatusBadgeProps {
  status: StatusType
  label?: string
  className?: string
  showDot?: boolean
}

const statusConfig: Record<StatusType, { 
  bg: string
  text: string
  ring: string
  dot: string
  defaultLabel: string
}> = {
  loading: {
    bg: 'bg-slate-500/10',
    text: 'text-slate-300',
    ring: 'ring-slate-500/20',
    dot: 'bg-slate-400',
    defaultLabel: 'Loading...',
  },
  error: {
    bg: 'bg-rose-500/10',
    text: 'text-rose-300',
    ring: 'ring-rose-500/20',
    dot: 'bg-rose-400',
    defaultLabel: 'Error',
  },
  warning: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-300',
    ring: 'ring-amber-500/20',
    dot: 'bg-amber-400',
    defaultLabel: 'Warning',
  },
  success: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    ring: 'ring-emerald-500/20',
    dot: 'bg-emerald-400',
    defaultLabel: 'Success',
  },
  info: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-300',
    ring: 'ring-blue-500/20',
    dot: 'bg-blue-400',
    defaultLabel: 'Info',
  },
  demo: {
    bg: 'bg-[#6B5AED]/10',
    text: 'text-[#A599FF]',
    ring: 'ring-[#6B5AED]/20',
    dot: 'bg-[#8B7CF7]',
    defaultLabel: 'Demo',
  },
  live: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    ring: 'ring-emerald-500/20',
    dot: 'bg-emerald-400',
    defaultLabel: 'Live',
  },
}

/**
 * Elegant status badge with subtle ring border and optional animated dot.
 * Apple-like design with toned-down colors and refined typography.
 */
export function StatusBadge({
  status,
  label,
  className = '',
  showDot = true,
}: StatusBadgeProps) {
  const config = statusConfig[status]
  const displayLabel = label || config.defaultLabel

  return (
    <div
      className={`
        inline-flex items-center gap-1.5 
        px-2.5 py-1 rounded-full
        ${config.bg} ${config.text}
        ring-1 ${config.ring}
        text-[11px] font-medium tracking-wide
        transition-all duration-200
        ${className}
      `}
    >
      {showDot && (
        status === 'loading' ? (
          <Loader2 size={10} className="animate-spin" />
        ) : (
          <span className={`w-1.5 h-1.5 rounded-full ${config.dot} animate-pulse`} />
        )
      )}
      <span>{displayLabel}</span>
    </div>
  )
}

export default StatusBadge
