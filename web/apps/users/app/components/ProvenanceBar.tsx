'use client'

import { Shield, GitCommit, Clock, CheckCircle, AlertCircle } from 'lucide-react'

interface ProvenanceBarProps {
  mode?: 'demo' | 'live'
  runId?: string
  commitSha?: string
  timestamp?: string
  signatureVerified?: boolean
}

export default function ProvenanceBar({
  mode = 'demo',
  runId = 'run-2024-001-demo',
  commitSha = 'c70dcd5',
  timestamp = new Date().toISOString(),
  signatureVerified = true,
}: ProvenanceBarProps) {
  const isDemo = mode === 'demo'
  
  return (
    <div className={`border-b ${isDemo ? 'bg-yellow-950/20 border-yellow-900/30' : 'bg-emerald-950/20 border-emerald-900/30'}`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-10 text-xs">
          {/* Left side - Mode indicator */}
          <div className="flex items-center gap-4">
            <div className={`flex items-center gap-1.5 px-2 py-1 rounded ${isDemo ? 'bg-yellow-900/30 text-yellow-400' : 'bg-emerald-900/30 text-emerald-400'}`}>
              <Shield className="w-3.5 h-3.5" />
              <span className="font-medium">{isDemo ? 'Demo Mode' : 'Live Production'}</span>
            </div>
            
            {isDemo && (
              <span className="text-yellow-400/70">
                Showing synthetic demo data for evaluation
              </span>
            )}
          </div>

          {/* Right side - Provenance metadata */}
          <div className="flex items-center gap-6 text-gray-400">
            {/* Run ID */}
            <div className="flex items-center gap-1.5">
              <span className="text-gray-500">Run:</span>
              <code className="text-gray-300 font-mono">{runId}</code>
            </div>

            {/* Commit SHA */}
            <div className="flex items-center gap-1.5">
              <GitCommit className="w-3.5 h-3.5 text-gray-500" />
              <code className="text-gray-300 font-mono">{commitSha}</code>
            </div>

            {/* Timestamp */}
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-gray-500" />
              <span className="text-gray-300">
                {new Date(timestamp).toLocaleString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </span>
            </div>

            {/* Signature verification */}
            <div className="flex items-center gap-1.5">
              {signatureVerified ? (
                <>
                  <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                  <span className="text-emerald-400">Verified</span>
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5 text-red-500" />
                  <span className="text-red-400">Unverified</span>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
