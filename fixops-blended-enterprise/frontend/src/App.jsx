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
        <Route path="/" element={<Navigate to="/developer" replace />} />
        <Route path="/developer" element={<DeveloperDashboard />} />
        <Route path="/ciso" element={<CISODashboard />} />
        <Route path="/architect" element={<ArchitectDashboard />} />
        <Route path="/upload" element={<ScanUploadPage />} />
        <Route path="/marketplace" element={<MarketplacePage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/services" element={<ServiceManagement />} />
        <Route path="*" element={<Navigate to="/developer" replace />} />
      </Routes>
    </Layout>
  )
}

export default App