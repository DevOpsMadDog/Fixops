import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import SecurityLayout from './components/SecurityLayout'
import CommandCenter from './pages/CommandCenter'
import DeveloperOps from './pages/DeveloperOps'
import ExecutiveBriefing from './pages/ExecutiveBriefing'
import ArchitectureCenter from './pages/ArchitectureCenter'
import InstallPage from './pages/InstallPage'
import ArchitecturePage from './pages/ArchitecturePage'
import TriageQueue from './pages/TriageQueue'
import RiskExplorer from './pages/RiskExplorer'
import ComplianceRollup from './pages/ComplianceRollup'
import EvidenceTimeline from './pages/EvidenceTimeline'

function App() {
  return (
    <SecurityLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/enhanced" replace />} />
        <Route path="/enhanced" element={<CommandCenter />} />
        <Route path="/developer" element={<DeveloperOps />} />
        <Route path="/ciso" element={<ExecutiveBriefing />} />
        <Route path="/architect" element={<ArchitectureCenter />} />
        <Route path="/install" element={<InstallPage />} />
        <Route path="/architecture" element={<ArchitecturePage />} />
        <Route path="/triage" element={<TriageQueue />} />
        <Route path="/risk" element={<RiskExplorer />} />
        <Route path="/compliance" element={<ComplianceRollup />} />
        <Route path="/evidence" element={<EvidenceTimeline />} />
        <Route path="*" element={<Navigate to="/enhanced" replace />} />
      </Routes>
    </SecurityLayout>
  )
}

export default App
