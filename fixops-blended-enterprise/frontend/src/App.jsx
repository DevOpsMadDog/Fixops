import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import EnhancedDashboard from './pages/EnhancedDashboard'
import DeveloperDashboard from './pages/DeveloperDashboard'
import CISODashboard from './pages/CISODashboard'
import ArchitectDashboard from './pages/ArchitectDashboard'
import ScanUploadPage from './pages/ScanUploadPage'
import MarketplacePage from './pages/MarketplacePage'
import AnalyticsPage from './pages/AnalyticsPage'
import InstallPage from './pages/InstallPage'
import ArchitecturePage from './pages/ArchitecturePage'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/enhanced" replace />} />
        <Route path="/enhanced" element={<EnhancedDashboard />} />
        <Route path="/developer" element={<DeveloperDashboard />} />
        <Route path="/ciso" element={<CISODashboard />} />
        <Route path="/architect" element={<ArchitectDashboard />} />
        <Route path="/upload" element={<ScanUploadPage />} />
        <Route path="/marketplace" element={<MarketplacePage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/install" element={<InstallPage />} />
        <Route path="/architecture" element={<ArchitecturePage />} />
        <Route path="*" element={<Navigate to="/enhanced" replace />} />
      </Routes>
    </Layout>
  )
}

export default App
