import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import './App.css';

// Components
import Sidebar from './components/Sidebar';
import DeveloperDashboard from './components/DeveloperDashboard';
import CISODashboard from './components/CISODashboard';
import ArchitectDashboard from './components/ArchitectDashboard';
import ServiceManagement from './components/ServiceManagement';
import FindingsExplorer from './components/FindingsExplorer';
import PolicyEngine from './components/PolicyEngine';
import CorrelatedCases from './components/CorrelatedCases';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen bg-gray-50">
      <Sidebar open={sidebarOpen} setOpen={setSidebarOpen} />
      <div className={`flex-1 flex flex-col overflow-hidden ${sidebarOpen ? 'ml-64' : 'ml-16'} transition-all duration-300`}>
        <header className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold text-gray-900">FixOps Control Plane</h1>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-sm text-gray-600">Real-time Security</span>
              </div>
              <div className="text-sm text-gray-500">
                Fintech Production Environment
              </div>
            </div>
          </div>
        </header>
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="App">
          <Routes>
            <Route path="/" element={<Navigate to="/developer" replace />} />
            <Route path="/developer" element={
              <Layout>
                <DeveloperDashboard />
              </Layout>
            } />
            <Route path="/ciso" element={
              <Layout>
                <CISODashboard />
              </Layout>
            } />
            <Route path="/architect" element={
              <Layout>
                <ArchitectDashboard />
              </Layout>
            } />
            <Route path="/services" element={
              <Layout>
                <ServiceManagement />
              </Layout>
            } />
            <Route path="/findings" element={
              <Layout>
                <FindingsExplorer />
              </Layout>
            } />
            <Route path="/policies" element={
              <Layout>
                <PolicyEngine />
              </Layout>
            } />
            <Route path="/cases" element={
              <Layout>
                <CorrelatedCases />
              </Layout>
            } />
          </Routes>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;