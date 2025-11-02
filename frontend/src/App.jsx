import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import TriageInbox from './pages/TriageInbox'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/triage" replace />} />
      <Route path="/triage" element={<TriageInbox />} />
      <Route path="*" element={<Navigate to="/triage" replace />} />
    </Routes>
  )
}

export default App
