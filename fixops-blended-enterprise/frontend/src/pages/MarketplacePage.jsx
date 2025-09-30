import React, { useState, useEffect } from 'react'

function MarketplacePage() {
  const [marketplaceItems, setMarketplaceItems] = useState([])
  const [filters, setFilters] = useState({
    content_type: '',
    compliance_frameworks: '',
    ssdlc_stages: '',
    pricing_model: '',
    organization_type: ''
  })
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState(null)

  useEffect(() => {
    fetchMarketplaceData()
  }, [filters])

  const fetchMarketplaceData = async () => {
    try {
      const queryParams = new URLSearchParams()
      Object.entries(filters).forEach(([key, value]) => {
        if (value) queryParams.append(key, value)
      })
      
      const [itemsRes, statsRes] = await Promise.all([
        fetch(`/api/v1/marketplace/browse?${queryParams}`),
        fetch('/api/v1/marketplace/stats')
      ])
      
      const [itemsData, statsData] = await Promise.all([
        itemsRes.json(),
        statsRes.json()
      ])
      
      setMarketplaceItems(itemsData.data?.items || [])
      setStats(statsData.data || {})
    } catch (error) {
      console.error('Failed to fetch marketplace data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleFilterChange = (filterName, value) => {
    setFilters(prev => ({
      ...prev,
      [filterName]: value
    }))
  }

  const getPriceDisplay = (item) => {
    if (item.pricing_model === 'free') {
      return '🆓 FREE'
    } else if (item.pricing_model === 'paid') {
      return `💰 $${item.price}`
    } else if (item.pricing_model === 'subscription') {
      return `📅 $${item.price}/month`
    } else {
      return `⚡ $${item.price}/use`
    }
  }

  const getContentTypeIcon = (contentType) => {
    const icons = {
      'golden_regression_set': '🏆',
      'compliance_framework': '📋',
      'security_patterns': '🔍',
      'policy_templates': '📜', 
      'threat_models': '🎯',
      'audit_checklists': '✅',
      'test_cases': '🧪'
    }
    return icons[contentType] || '📦'
  }

  return (
    <div style={{
      padding: '2rem',
      maxWidth: '1600px',
      margin: '0 auto',
      backgroundColor: '#f8fafc',
      minHeight: '100vh'
    }}>
      
      {/* Header */}
      <div style={{ marginBottom: '2rem', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '2.5rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.5rem'
        }}>
          FixOps Security Marketplace
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.125rem',
          marginBottom: '1.5rem'
        }}>
          Discover, contribute, and monetize security compliance content
        </p>
        
        {/* Marketplace Stats */}
        {stats && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: '1rem',
            maxWidth: '800px',
            margin: '0 auto'
          }}>
            <div style={{
              backgroundColor: 'white',
              padding: '1rem',
              borderRadius: '12px',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#2563eb' }}>
                {stats.total_items}
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                Content Items
              </div>
            </div>
            <div style={{
              backgroundColor: 'white',
              padding: '1rem',
              borderRadius: '12px',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#16a34a' }}>
                {stats.total_downloads}
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                Downloads
              </div>
            </div>
            <div style={{
              backgroundColor: 'white',
              padding: '1rem',
              borderRadius: '12px',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#7c3aed' }}>
                {stats.average_rating?.toFixed(1) || '4.8'}
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                Avg Rating
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Filters */}
      <div style={{
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
        marginBottom: '2rem'
      }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#1f2937', marginBottom: '1rem' }}>
          🔍 Browse & Filter Content
        </h2>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem'
        }}>
          <div>
            <label style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', display: 'block', marginBottom: '0.5rem' }}>
              Content Type
            </label>
            <select
              value={filters.content_type}
              onChange={(e) => handleFilterChange('content_type', e.target.value)}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                fontSize: '0.875rem'
              }}
            >
              <option value="">All Types</option>
              <option value="golden_regression_set">🏆 Golden Regression Sets</option>
              <option value="compliance_framework">📋 Compliance Frameworks</option>
              <option value="security_patterns">🔍 Security Patterns</option>
              <option value="policy_templates">📜 Policy Templates</option>
              <option value="threat_models">🎯 Threat Models</option>
              <option value="audit_checklists">✅ Audit Checklists</option>
              <option value="test_cases">🧪 Test Cases</option>
            </select>
          </div>
          
          <div>
            <label style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', display: 'block', marginBottom: '0.5rem' }}>
              Compliance Frameworks
            </label>
            <select
              value={filters.compliance_frameworks}
              onChange={(e) => handleFilterChange('compliance_frameworks', e.target.value)}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                fontSize: '0.875rem'
              }}
            >
              <option value="">All Frameworks</option>
              <option value="pci_dss">💳 PCI DSS</option>
              <option value="sox">📊 SOX</option>
              <option value="hipaa">🏥 HIPAA</option>
              <option value="nist_ssdf">🛡️ NIST SSDF</option>
              <option value="soc2">🔒 SOC2</option>
              <option value="owasp">🌐 OWASP</option>
              <option value="iso27001">📜 ISO 27001</option>
            </select>
          </div>
          
          <div>
            <label style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', display: 'block', marginBottom: '0.5rem' }}>
              SSDLC Stage
            </label>
            <select
              value={filters.ssdlc_stages}
              onChange={(e) => handleFilterChange('ssdlc_stages', e.target.value)}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                fontSize: '0.875rem'
              }}
            >
              <option value="">All Stages</option>
              <option value="plan">📋 Plan</option>
              <option value="code">🔍 Code</option>
              <option value="build">📦 Build</option>
              <option value="test">🧪 Test</option>
              <option value="release">🚀 Release</option>
              <option value="deploy">🏗️ Deploy</option>
              <option value="operate">⚙️ Operate</option>
            </select>
          </div>
          
          <div>
            <label style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', display: 'block', marginBottom: '0.5rem' }}>
              Pricing
            </label>
            <select
              value={filters.pricing_model}
              onChange={(e) => handleFilterChange('pricing_model', e.target.value)}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                fontSize: '0.875rem'
              }}
            >
              <option value="">All Pricing</option>
              <option value="free">🆓 Free</option>
              <option value="paid">💰 Paid</option>
              <option value="subscription">📅 Subscription</option>
              <option value="pay_per_use">⚡ Pay Per Use</option>
            </select>
          </div>
          
          <div>
            <label style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151', display: 'block', marginBottom: '0.5rem' }}>
              Industry
            </label>
            <select
              value={filters.organization_type}
              onChange={(e) => handleFilterChange('organization_type', e.target.value)}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                fontSize: '0.875rem'
              }}
            >
              <option value="">All Industries</option>
              <option value="financial">🏦 Financial Services</option>
              <option value="healthcare">🏥 Healthcare</option>
              <option value="government">🏛️ Government</option>
              <option value="technology">💻 Technology</option>
              <option value="manufacturing">🏭 Manufacturing</option>
              <option value="retail">🛒 Retail</option>
            </select>
          </div>
        </div>
      </div>

      {/* Marketplace Items Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: '2rem'
      }}>
        {marketplaceItems.map((item) => (
          <div key={item.id} style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '16px',
            boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
            border: '1px solid #e5e7eb'
          }}>
            {/* Item Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span style={{ fontSize: '2rem', marginRight: '0.75rem' }}>
                  {getContentTypeIcon(item.content_type)}
                </span>
                <div>
                  <h3 style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', margin: 0 }}>
                    {item.name}
                  </h3>
                  <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                    by {item.author} • {item.organization}
                  </p>
                </div>
              </div>
              
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '1rem', fontWeight: '700', color: '#2563eb', marginBottom: '0.25rem' }}>
                  {getPriceDisplay(item)}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', fontSize: '0.75rem', color: '#6b7280' }}>
                  <span style={{ marginRight: '0.5rem' }}>⭐ {item.rating}</span>
                  <span>📥 {item.downloads}</span>
                </div>
              </div>
            </div>
            
            {/* Description */}
            <p style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '1rem', lineHeight: '1.5' }}>
              {item.description}
            </p>
            
            {/* Compliance Frameworks */}
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>
                COMPLIANCE FRAMEWORKS:
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {item.compliance_frameworks.map((framework) => (
                  <span key={framework} style={{
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    color: '#2563eb',
                    backgroundColor: '#dbeafe',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '12px'
                  }}>
                    {framework.toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
            
            {/* SSDLC Stages */}
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>
                SSDLC STAGES:
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {item.ssdlc_stages.map((stage) => (
                  <span key={stage} style={{
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    color: '#16a34a',
                    backgroundColor: '#dcfce7',
                    padding: '0.25rem 0.5rem',
                    borderRadius: '12px'
                  }}>
                    {stage.toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
            
            {/* Metadata */}
            {item.metadata && Object.keys(item.metadata).length > 0 && (
              <div style={{
                backgroundColor: '#f8fafc',
                padding: '1rem',
                borderRadius: '8px',
                border: '1px solid #e5e7eb',
                marginBottom: '1rem'
              }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '600', color: '#374151', marginBottom: '0.5rem' }}>
                  CONTENT DETAILS:
                </div>
                {Object.entries(item.metadata).map(([key, value]) => (
                  <div key={key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#6b7280' }}>
                    <span>{key.replace('_', ' ')}:</span>
                    <span style={{ fontWeight: '600' }}>{typeof value === 'number' ? value.toLocaleString() : String(value)}</span>
                  </div>
                ))}
              </div>
            )}
            
            {/* Action Buttons */}
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                onClick={() => console.log('Download/Purchase:', item.id)}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  backgroundColor: item.pricing_model === 'free' ? '#16a34a' : '#2563eb',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                {item.pricing_model === 'free' ? '📥 Download' : '💰 Purchase'}
              </button>
              <button
                onClick={() => console.log('View details:', item.id)}
                style={{
                  padding: '0.75rem 1rem',
                  backgroundColor: 'transparent',
                  color: '#6b7280',
                  border: '1px solid #d1d5db',
                  borderRadius: '8px',
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                👁️ Details
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Contribution Section */}
      <div style={{
        marginTop: '3rem',
        backgroundColor: 'white',
        padding: '2rem',
        borderRadius: '16px',
        boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
        border: '1px solid #e5e7eb',
        textAlign: 'center'
      }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#1f2937', marginBottom: '1rem' }}>
          💡 Contribute to the Marketplace
        </h2>
        <p style={{ fontSize: '1rem', color: '#6b7280', marginBottom: '1.5rem' }}>
          Share your security expertise and earn from your compliance knowledge
        </p>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          marginBottom: '2rem'
        }}>
          <div style={{ padding: '1rem', backgroundColor: '#f0f9ff', borderRadius: '8px' }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🏆</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>Golden Test Sets</div>
            <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Audit test cases</div>
          </div>
          <div style={{ padding: '1rem', backgroundColor: '#f0fdf4', borderRadius: '8px' }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>📋</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>Compliance Frameworks</div>
            <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Industry standards</div>
          </div>
          <div style={{ padding: '1rem', backgroundColor: '#fef3c7', borderRadius: '8px' }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>🔍</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>Security Patterns</div>
            <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Threat detection</div>
          </div>
          <div style={{ padding: '1rem', backgroundColor: '#f3e8ff', borderRadius: '8px' }}>
            <div style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>📜</div>
            <div style={{ fontSize: '0.875rem', fontWeight: '600', color: '#1f2937' }}>Policy Templates</div>
            <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>OPA/Rego policies</div>
          </div>
        </div>
        
        <button
          onClick={() => console.log('Open contribution form')}
          style={{
            padding: '1rem 2rem',
            backgroundColor: '#7c3aed',
            color: 'white',
            border: 'none',
            borderRadius: '12px',
            fontSize: '1rem',
            fontWeight: '700',
            cursor: 'pointer'
          }}
        >
          🚀 Start Contributing
        </button>
      </div>
    </div>
  )
}

export default MarketplacePage