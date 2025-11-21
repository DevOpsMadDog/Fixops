import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import RiskGraph from './pages/RiskGraph'
import TriageInbox from './pages/TriageInbox'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/risk" replace />} />
      <Route path="/risk" element={<RiskGraph />} />
      <Route path="/triage" element={<TriageInbox />} />
      <Route path="*" element={<Navigate to="/risk" replace />} />
    </Routes>
  )
}

export default App
