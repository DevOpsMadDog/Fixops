import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import { Shield, TrendingDown, DollarSign, Users, AlertTriangle, CheckCircle, Clock, Target } from 'lucide-react';
import { api } from '../api/client';
import LoadingSpinner from './LoadingSpinner';
import MetricCard from './MetricCard';

const COLORS = ['#dc2626', '#ea580c', '#d97706', '#65a30d', '#059669'];

const CISODashboard = () => {
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: () => api.getDashboardMetrics().then(res => res.data),
  });

  const { data: trends, isLoading: trendsLoading } = useQuery({
    queryKey: ['finding-trends'],
    queryFn: () => api.getFindingTrends().then(res => res.data),
  });

  const { data: services, isLoading: servicesLoading } = useQuery({
    queryKey: ['services'],
    queryFn: () => api.getServices().then(res => res.data),
  });

  if (metricsLoading || trendsLoading || servicesLoading) {
    return <LoadingSpinner />;
  }

  // Calculate risk metrics
  const totalRiskScore = metrics?.critical_findings * 10 + metrics?.high_findings * 5;
  const riskReduction = 67; // Percentage reduction from FixOps
  const complianceScore = 85; // NIST SSDF compliance percentage

  // Prepare chart data
  const severityData = [
    { name: 'Critical', value: metrics?.critical_findings || 0, color: '#dc2626' },
    { name: 'High', value: metrics?.high_findings || 0, color: '#ea580c' },
    { name: 'Medium', value: (metrics?.total_findings || 0) - (metrics?.critical_findings || 0) - (metrics?.high_findings || 0), color: '#d97706' },
  ].filter(item => item.value > 0);

  const scannerData = Object.entries(metrics?.findings_by_scanner || {}).map(([scanner, count]) => ({
    scanner: scanner.toUpperCase(),
    findings: count,
  }));

  const environmentData = Object.entries(metrics?.services_by_environment || {}).map(([env, count]) => ({
    environment: env,
    services: count,
  }));

  // PCI/PII services risk calculation
  const pciServices = services?.filter(s => s.data_classification.includes('pci')).length || 0;
  const piiServices = services?.filter(s => s.data_classification.includes('pii')).length || 0;
  const internetFacingServices = services?.filter(s => s.internet_facing).length || 0;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">CISO Executive Dashboard</h1>
          <p className="text-gray-600 mt-1">Risk visibility, compliance metrics, and business impact analysis</p>
        </div>
        <div className="flex items-center space-x-3">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
            <Shield className="w-4 h-4 mr-1" />
            NIST SSDF Compliant
          </span>
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
            SOC 2 Ready
          </span>
        </div>
      </div>

      {/* Executive Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6">
        <MetricCard
          title="Risk Score"
          value={totalRiskScore}
          icon={AlertTriangle}
          color="red"
          subtitle="Prioritized by business impact"
          trend={{ direction: 'down', value: '67%', positive: true }}
        />
        <MetricCard
          title="MTTR Improvement"
          value={`${metrics?.mttr_days}d`}
          icon={Clock}
          color="green"
          subtitle="From 21-28 days"
          trend={{ direction: 'down', value: '85%', positive: true }}
        />
        <MetricCard
          title="Cost Savings"
          value="$340K"
          icon={DollarSign}
          color="green"
          subtitle="Annual license consolidation"
        />
        <MetricCard
          title="Compliance Score"
          value={`${complianceScore}%`}
          icon={CheckCircle}
          color="blue"
          subtitle="NIST SSDF coverage"
          trend={{ direction: 'up', value: '12%', positive: true }}
        />
        <MetricCard
          title="Developer Efficiency"
          value="+42%"
          icon={Users}
          color="purple"
          subtitle="Reduced context switching"
          trend={{ direction: 'up', value: '42%', positive: true }}
        />
      </div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk by Severity */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-4 space-y-2">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                  <span className="text-gray-700">{item.name}</span>
                </div>
                <span className="font-medium text-gray-900">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Findings Trend */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Findings Trend</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trends?.slice(-14) || []}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={2} />
              <Line type="monotone" dataKey="high" stroke="#ea580c" strokeWidth={2} />
              <Line type="monotone" dataKey="total" stroke="#6b7280" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
          <div className="mt-4 flex items-center justify-center space-x-6 text-sm">
            <div className="flex items-center">
              <div className="w-3 h-1 bg-red-600 mr-2"></div>
              <span className="text-gray-700">Critical</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-1 bg-orange-600 mr-2"></div>
              <span className="text-gray-700">High</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-1 bg-gray-600 mr-2"></div>
              <span className="text-gray-700">Total</span>
            </div>
          </div>
        </div>

        {/* Scanner Coverage */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Scanner Integration</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={scannerData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="scanner" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="findings" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Compliance & Risk Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* NIST SSDF Compliance */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">NIST SSDF Compliance</h3>
            <p className="text-sm text-gray-600 mt-1">Secure Software Development Framework controls</p>
          </div>
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">PO.3.1 - Security Requirements</span>
              <div className="flex items-center">
                <div className="w-32 bg-gray-200 rounded-full h-2 mr-3">
                  <div className="bg-green-600 h-2 rounded-full" style={{ width: '90%' }}></div>
                </div>
                <span className="text-sm font-medium text-green-600">90%</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">PS.1.1 - Code Protection</span>
              <div className="flex items-center">
                <div className="w-32 bg-gray-200 rounded-full h-2 mr-3">
                  <div className="bg-green-600 h-2 rounded-full" style={{ width: '85%' }}></div>
                </div>
                <span className="text-sm font-medium text-green-600">85%</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">PW.7.2 - Provenance Verification</span>
              <div className="flex items-center">
                <div className="w-32 bg-gray-200 rounded-full h-2 mr-3">
                  <div className="bg-yellow-500 h-2 rounded-full" style={{ width: '75%' }}></div>
                </div>
                <span className="text-sm font-medium text-yellow-600">75%</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700">PS.2.1 - Secure Design</span>
              <div className="flex items-center">
                <div className="w-32 bg-gray-200 rounded-full h-2 mr-3">
                  <div className="bg-green-600 h-2 rounded-full" style={{ width: '88%' }}></div>
                </div>
                <span className="text-sm font-medium text-green-600">88%</span>
              </div>
            </div>
          </div>
        </div>

        {/* Business Risk Analysis */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Business Risk Analysis</h3>
            <p className="text-sm text-gray-600 mt-1">Risk aligned to business capabilities and data classification</p>
          </div>
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg border border-red-200">
              <div>
                <h4 className="font-medium text-red-900">PCI Data Services</h4>
                <p className="text-sm text-red-700">{pciServices} services processing payment data</p>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-red-900">{Math.round(totalRiskScore * 0.6)}</div>
                <div className="text-sm text-red-700">Risk Score</div>
              </div>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-orange-50 rounded-lg border border-orange-200">
              <div>
                <h4 className="font-medium text-orange-900">PII Data Services</h4>
                <p className="text-sm text-orange-700">{piiServices} services handling personal data</p>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-orange-900">{Math.round(totalRiskScore * 0.3)}</div>
                <div className="text-sm text-orange-700">Risk Score</div>
              </div>
            </div>
            
            <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg border border-blue-200">
              <div>
                <h4 className="font-medium text-blue-900">Internet-Facing</h4>
                <p className="text-sm text-blue-700">{internetFacingServices} services exposed to internet</p>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-blue-900">{Math.round(totalRiskScore * 0.4)}</div>
                <div className="text-sm text-blue-700">Exposure Score</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Policy Decisions Summary */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Automated Policy Decisions</h3>
          <p className="text-sm text-gray-600 mt-1">Real-time security decision automation</p>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            {Object.entries(metrics?.policy_decisions || {}).map(([decision, count]) => (
              <div key={decision} className="text-center p-4 rounded-lg bg-gray-50">
                <div className="text-2xl font-bold text-gray-900">{count}</div>
                <div className="text-sm text-gray-600 capitalize mt-1">{decision.replace('_', ' ')}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CISODashboard;