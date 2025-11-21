'use client'

import { useEffect } from 'react'

export default function ShellPage() {
  useEffect(() => {
    window.location.href = '/triage'
  }, [])

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0f172a] font-sans text-white">
      <div className="text-center">
        <div className="mb-4">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-[#6B5AED]"></div>
        </div>
        <p className="text-sm text-slate-400">Loading FixOps...</p>
      </div>
    </div>
  )
}
