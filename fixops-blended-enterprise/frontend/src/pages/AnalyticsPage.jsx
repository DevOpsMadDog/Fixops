import React from 'react'
import { BarChart3, TrendingUp, PieChart, Activity, Calendar, Download } from 'lucide-react'

function AnalyticsPage() {
  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg leading-6 font-medium text-gray-900">
              Security Analytics
            </h3>
            <p className="mt-2 max-w-4xl text-sm text-gray-500">
              Comprehensive security metrics and trend analysis
            </p>
          </div>
          <button className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <TrendingUp className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Risk Reduction
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">34%</dd>
                  <dd className="text-xs text-green-600">+12% this month</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Activity className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    MTTR
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">2.4h</dd>
                  <dd className="text-xs text-green-600">-15% improvement</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <BarChart3 className="h-6 w-6 text-purple-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Policy Automation
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">89%</dd>
                  <dd className="text-xs text-blue-600">24 active policies</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <PieChart className="h-6 w-6 text-orange-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Correlation Rate
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">65%</dd>
                  <dd className="text-xs text-gray-600">noise reduction</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Finding Trends (30 days)</h3>
            <div className="h-64 bg-gray-50 rounded-lg flex items-center justify-center">
              <div className="text-center">
                <BarChart3 className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <p className="text-gray-500">Chart visualization would be here</p>
                <p className="text-xs text-gray-400 mt-1">
                  Integration with Recharts for live data visualization
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Severity Distribution</h3>
            <div className="h-64 bg-gray-50 rounded-lg flex items-center justify-center">
              <div className="text-center">
                <PieChart className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <p className="text-gray-500">Pie chart would be here</p>
                <div className="text-xs text-gray-600 mt-2 space-y-1">
                  <div>Critical: 8 (6%)</div>
                  <div>High: 34 (27%)</div>
                  <div>Medium: 52 (41%)</div>
                  <div>Low: 33 (26%)</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Performance Analytics</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600 mb-1">285μs</div>
              <div className="text-sm text-gray-500">Average Hot Path Latency</div>
              <div className="text-xs text-green-600 mt-1">✓ Under 299μs target</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600 mb-1">99.7%</div>
              <div className="text-sm text-gray-500">API Availability</div>
              <div className="text-xs text-gray-600 mt-1">Last 30 days</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600 mb-1">156ms</div>
              <div className="text-sm text-gray-500">Average Response Time</div>
              <div className="text-xs text-green-600 mt-1">-23% improvement</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AnalyticsPage