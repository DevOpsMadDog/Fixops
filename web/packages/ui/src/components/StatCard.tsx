'use client'

import { ReactNode } from 'react'

interface StatCardProps {
  label: string
  value: string | number
  icon?: ReactNode
  trend?: 'up' | 'down' | 'neutral'
  trendValue?: string
  color?: 'default' | 'purple' | 'green' | 'red' | 'amber' | 'blue'
  className?: string
}

const colors = {
  default: 'text-white',
  purple: 'text-[#A599FF]',
  green: 'text-emerald-400',
  red: 'text-rose-400',
  amber: 'text-amber-400',
  blue: 'text-blue-400',
}

/**
 * Premium stat card with glass-morphism styling.
 * Features refined typography, subtle gradients, and optional trend indicators.
 */
export function StatCard({
  label,
  value,
  icon,
  trend,
  trendValue,
  color = 'default',
  className = '',
}: StatCardProps) {
  return (
    <div
      className={`
        relative overflow-hidden
        p-4 rounded-xl
        bg-white/[0.03] backdrop-blur-xl
        ring-1 ring-white/[0.06]
        shadow-[0_1px_0_rgba(255,255,255,0.02),0_4px_12px_rgba(0,0,0,0.15)]
        transition-all duration-200 ease-out
        hover:bg-white/[0.05] hover:ring-white/[0.08]
        group
        ${className}
      `}
    >
      {/* Subtle top sheen */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-[11px] font-medium text-slate-500 uppercase tracking-wider">
            {label}
          </p>
          <p className={`text-2xl font-semibold tracking-tight tabular-nums ${colors[color]}`}>
            {value}
          </p>
          {trend && trendValue && (
            <p className={`text-[11px] font-medium ${
              trend === 'up' ? 'text-emerald-400' : 
              trend === 'down' ? 'text-rose-400' : 
              'text-slate-500'
            }`}>
              {trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→'} {trendValue}
            </p>
          )}
        </div>
        {icon && (
          <span className="text-slate-600 group-hover:text-slate-500 transition-colors duration-200">
            {icon}
          </span>
        )}
      </div>
    </div>
  )
}

export default StatCard
