import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import EnhancedDashboard from './pages/EnhancedDashboard'
import DeveloperDashboard from './pages/DeveloperDashboard'
import CISODashboard from './pages/CISODashboard'
import ScanUploadPage from './pages/ScanUploadPage'
import MarketplacePage from './pages/MarketplacePage'
import AnalyticsPage from './pages/AnalyticsPage'

function App() {
  // No authentication required - free tool
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/enhanced" replace />} />
        <Route path="/enhanced" element={<EnhancedDashboard />} />
        <Route path="/developer" element={<DeveloperDashboard />} />
        <Route path="/ciso" element={<CISODashboard />} />
        <Route path="/upload" element={<ScanUploadPage />} />
        <Route path="/marketplace" element={<MarketplacePage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="*" element={<Navigate to="/enhanced" replace />} />
      </Routes>
    </Layout>
  )
}

export default App