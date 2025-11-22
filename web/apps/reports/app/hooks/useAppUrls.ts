'use client'

import { useState, useEffect } from 'react'

interface AppUrls {
  dashboard: string
  triage: string
  risk: string
  compliance: string
  evidence: string
  findings: string
  'saved-views': string
  automations: string
  integrations: string
  settings: string
}

export function useAppUrls() {
  const [appUrls, setAppUrls] = useState<AppUrls | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/app-urls.json')
      .then(res => res.json())
      .then((urls: AppUrls) => {
        setAppUrls(urls)
        setLoading(false)
      })
      .catch(err => {
        console.error('Failed to load app URLs:', err)
        setLoading(false)
      })
  }, [])

  return { appUrls, loading }
}
