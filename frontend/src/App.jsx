import React, { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import LoadingSpinner from './components/LoadingSpinner'

const TriageInbox = lazy(() => import('./pages/TriageInbox'))
const RiskGraph = lazy(() => import('./pages/RiskGraph'))

const PageLoader = () => (
  <div
    style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '16px',
      background: '#0f172a',
      color: '#94a3b8',
      fontFamily: 'Inter, sans-serif',
      textAlign: 'center',
    }}
  >
    <LoadingSpinner size="lg" />
    <div>Loading the FixOps experience…</div>
  </div>
)

function App() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route path="/" element={<Navigate to="/triage" replace />} />
        <Route path="/triage" element={<TriageInbox />} />
        <Route path="/risk" element={<RiskGraph />} />
        <Route path="*" element={<Navigate to="/triage" replace />} />
      </Routes>
    </Suspense>
  )
}

export default App
