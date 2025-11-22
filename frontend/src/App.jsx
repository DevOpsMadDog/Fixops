import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import RiskGraph from './pages/RiskGraph'
import TriageInbox from './pages/TriageInbox'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/triage" replace />} />
      <Route path="/triage" element={<TriageInbox />} />
      <Route path="/risk" element={<RiskGraph />} />
      <Route path="*" element={<Navigate to="/triage" replace />} />
    </Routes>
  )
}

export default App
