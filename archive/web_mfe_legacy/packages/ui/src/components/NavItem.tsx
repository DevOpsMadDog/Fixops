'use client'

import { ReactNode } from 'react'

interface NavItemProps {
  icon?: ReactNode
  label: string
  count?: number
  active?: boolean
  onClick?: () => void
  href?: string
  className?: string
}

/**
 * Sleek sidebar navigation item with Apple-like styling.
 * Features pill-style active state, subtle hover effects, and refined typography.
 */
export function NavItem({
  icon,
  label,
  count,
  active = false,
  onClick,
  href,
  className = '',
}: NavItemProps) {
  const Component = href ? 'a' : 'button'
  const componentProps = href ? { href } : { onClick, type: 'button' as const }

  return (
    <Component
      {...componentProps}
      className={`
        w-full flex items-center justify-between
        px-3 py-2.5 rounded-xl
        text-[13px] font-medium
        transition-all duration-200 ease-out
        group
        ${active 
          ? 'bg-white/[0.08] text-white ring-1 ring-white/[0.1] shadow-[0_1px_0_rgba(255,255,255,0.04)]' 
          : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
        }
        ${className}
      `}
    >
      <span className="flex items-center gap-3">
        {icon && (
          <span className={`
            flex-shrink-0 transition-colors duration-200
            ${active ? 'text-[#8B7CF7]' : 'text-slate-500 group-hover:text-slate-400'}
          `}>
            {icon}
          </span>
        )}
        <span className="truncate">{label}</span>
      </span>
      {count !== undefined && (
        <span className={`
          px-2 py-0.5 rounded-md text-[11px] font-semibold tabular-nums
          transition-all duration-200
          ${active 
            ? 'bg-[#6B5AED]/20 text-[#A599FF]' 
            : 'bg-slate-800/80 text-slate-500 group-hover:bg-slate-700/80 group-hover:text-slate-400'
          }
        `}>
          {count}
        </span>
      )}
    </Component>
  )
}

export default NavItem
