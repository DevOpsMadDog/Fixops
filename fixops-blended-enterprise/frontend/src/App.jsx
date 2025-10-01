import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import NewLayout from './components/NewLayout'
import NewEnhancedDashboard from './pages/NewEnhancedDashboard'
import NewDeveloperDashboard from './pages/NewDeveloperDashboard'
import NewCISODashboard from './pages/NewCISODashboard'
import ArchitectDashboard from './pages/ArchitectDashboard'
import ScanUploadPage from './pages/ScanUploadPage'
import MarketplacePage from './pages/MarketplacePage'
import AnalyticsPage from './pages/AnalyticsPage'
import InstallPage from './pages/InstallPage'
import ArchitecturePage from './pages/ArchitecturePage'

function App() {
  return (
    <NewLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/enhanced" replace />} />
        <Route path="/enhanced" element={<NewEnhancedDashboard />} />
        <Route path="/developer" element={<NewDeveloperDashboard />} />
        <Route path="/ciso" element={<NewCISODashboard />} />
        <Route path="/architect" element={<ArchitectDashboard />} />
        <Route path="/upload" element={<ScanUploadPage />} />
        <Route path="/marketplace" element={<MarketplacePage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/install" element={<InstallPage />} />
        <Route path="/architecture" element={<ArchitecturePage />} />
        <Route path="*" element={<Navigate to="/enhanced" replace />} />
      </Routes>
    </NewLayout>
  )
}

export default App
