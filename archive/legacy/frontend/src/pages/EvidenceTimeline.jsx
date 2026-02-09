import React, { useState, useEffect } from 'react'
import aldeciTheme from '../theme/aldeci'

const EvidenceTimeline = () => {
  const [evidenceBundles, setEvidenceBundles] = useState([])
  const [loading, setLoading] = useState(true)
  const [retentionMode, setRetentionMode] = useState('demo') // demo or enterprise
  const [selectedBundle, setSelectedBundle] = useState(null)

  useEffect(() => {
    loadEvidenceBundles()
  }, [])

  const loadEvidenceBundles = async () => {
    try {
      const response = await fetch('/api/v1/ui/evidence')
      if (response.ok) {
        const data = await response.json()
        setEvidenceBundles(data.bundles || [])
        if (data.bundles && data.bundles.length > 0) {
          const retention = data.bundles[0].retention_days
          setRetentionMode(retention > 365 ? 'enterprise' : 'demo')
        }
      } else {
        setEvidenceBundles(generateDemoEvidenceBundles())
      }
    } catch (error) {
      console.error('Failed to load evidence bundles:', error)
      setEvidenceBundles(generateDemoEvidenceBundles())
    } finally {
      setLoading(false)
    }
  }

  const generateDemoEvidenceBundles = () => {
    const now = new Date()
    return [
      {
        run_id: 'run-2025-11-02-001',
        created_at: new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000).toISOString(),
        retention_days: 90,
        sections: ['design', 'sbom', 'sarif', 'cve', 'crosswalk', 'decisions', 'compliance'],
        sha256: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
        compressed: true,
        encrypted: false,
        size_bytes: 2458624,
        files: {
          manifest: '/data/evidence/run-2025-11-02-001/manifest.json',
          bundle: '/data/evidence/run-2025-11-02-001/bundle.tar.gz',
        },
      },
      {
        run_id: 'run-2025-11-01-003',
        created_at: new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString(),
        retention_days: 90,
        sections: ['design', 'sbom', 'sarif', 'cve', 'crosswalk', 'decisions'],
        sha256: 'b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7',
        compressed: true,
        encrypted: false,
        size_bytes: 2312456,
        files: {
          manifest: '/data/evidence/run-2025-11-01-003/manifest.json',
          bundle: '/data/evidence/run-2025-11-01-003/bundle.tar.gz',
        },
      },
      {
        run_id: 'run-2025-10-31-002',
        created_at: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000).toISOString(),
        retention_days: 90,
        sections: ['design', 'sbom', 'sarif', 'cve', 'crosswalk', 'decisions', 'compliance'],
        sha256: 'c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8',
        compressed: true,
        encrypted: false,
        size_bytes: 2567890,
        files: {
          manifest: '/data/evidence/run-2025-10-31-002/manifest.json',
          bundle: '/data/evidence/run-2025-10-31-002/bundle.tar.gz',
        },
      },
      {
        run_id: 'run-2025-10-30-001',
        created_at: new Date(now.getTime() - 4 * 24 * 60 * 60 * 1000).toISOString(),
        retention_days: 90,
        sections: ['design', 'sbom', 'sarif', 'cve', 'crosswalk'],
        sha256: 'd4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9',
        compressed: true,
        encrypted: false,
        size_bytes: 2145678,
        files: {
          manifest: '/data/evidence/run-2025-10-30-001/manifest.json',
          bundle: '/data/evidence/run-2025-10-30-001/bundle.tar.gz',
        },
      },
      {
        run_id: 'run-2025-10-29-004',
        created_at: new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        retention_days: 90,
        sections: ['design', 'sbom', 'sarif', 'cve', 'crosswalk', 'decisions', 'compliance'],
        sha256: 'e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0',
        compressed: true,
        encrypted: false,
        size_bytes: 2678901,
        files: {
          manifest: '/data/evidence/run-2025-10-29-004/manifest.json',
          bundle: '/data/evidence/run-2025-10-29-004/bundle.tar.gz',
        },
      },
    ]
  }

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const getRetentionBadgeColor = () => {
    return retentionMode === 'enterprise' ? aldeciTheme.colors.primary : aldeciTheme.colors.info
  }

  const downloadBundle = (bundle) => {
    console.log('Downloading bundle:', bundle.run_id)
    alert(`Downloading evidence bundle: ${bundle.run_id}\nSize: ${formatBytes(bundle.size_bytes)}`)
  }

  const viewManifest = (bundle) => {
    setSelectedBundle(bundle)
  }

  if (loading) {
    return (
      <div style={{
        height: '100vh',
        background: aldeciTheme.colors.bgPrimary,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        color: aldeciTheme.colors.textPrimary,
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: '60px',
            height: '60px',
            border: `4px solid ${aldeciTheme.colors.borderPrimary}`,
            borderTop: `4px solid ${aldeciTheme.colors.primary}`,
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 1rem auto',
          }}></div>
          <h2 style={{ fontSize: aldeciTheme.typography.fontSize.lg, fontWeight: aldeciTheme.typography.fontWeight.semibold }}>
            Loading Evidence Bundles...
          </h2>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      background: aldeciTheme.colors.bgPrimary,
      minHeight: '100vh',
      color: aldeciTheme.colors.textPrimary,
      padding: aldeciTheme.spacing.md,
      fontFamily: aldeciTheme.typography.fontFamily,
    }}>
      <div style={{ maxWidth: '1800px', margin: '0 auto' }}>
        
        {/* Header */}
        <div style={{
          marginBottom: aldeciTheme.spacing.lg,
        }}>
          <h1 style={{
            fontSize: aldeciTheme.typography.fontSize.xxl,
            fontWeight: aldeciTheme.typography.fontWeight.bold,
            margin: 0,
          }}>
            Evidence Timeline
          </h1>
          <p style={{
            fontSize: aldeciTheme.typography.fontSize.base,
            color: aldeciTheme.colors.textSecondary,
            margin: `${aldeciTheme.spacing.xs} 0 0 0`,
          }}>
            Cryptographically-signed evidence bundles with {retentionMode === 'enterprise' ? '7-year' : '90-day'} retention
          </p>
        </div>

        {/* Retention Mode Badge */}
        <div style={{
          marginBottom: aldeciTheme.spacing.lg,
        }}>
          <span style={{
            padding: `${aldeciTheme.spacing.sm} ${aldeciTheme.spacing.md}`,
            backgroundColor: getRetentionBadgeColor(),
            borderRadius: aldeciTheme.borderRadius.md,
            fontSize: aldeciTheme.typography.fontSize.base,
            fontWeight: aldeciTheme.typography.fontWeight.semibold,
            display: 'inline-block',
          }}>
            {retentionMode === 'enterprise' ? '🏢 Enterprise Mode (2555 days)' : '🧪 Demo Mode (90 days)'}
          </span>
        </div>

        {/* Summary Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: aldeciTheme.spacing.md,
          marginBottom: aldeciTheme.spacing.lg,
        }}>
          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              color: aldeciTheme.colors.textSecondary,
              textTransform: 'uppercase',
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            }}>
              Total Bundles
            </h3>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xxl,
              fontWeight: aldeciTheme.typography.fontWeight.bold,
              color: aldeciTheme.colors.textPrimary,
            }}>
              {evidenceBundles.length}
            </div>
          </div>

          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              color: aldeciTheme.colors.textSecondary,
              textTransform: 'uppercase',
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            }}>
              Total Storage
            </h3>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xxl,
              fontWeight: aldeciTheme.typography.fontWeight.bold,
              color: aldeciTheme.colors.textPrimary,
            }}>
              {formatBytes(evidenceBundles.reduce((sum, b) => sum + b.size_bytes, 0))}
            </div>
          </div>

          <div style={{
            background: aldeciTheme.colors.bgCard,
            borderRadius: aldeciTheme.borderRadius.lg,
            border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            padding: aldeciTheme.spacing.md,
            boxShadow: aldeciTheme.shadows.md,
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.sm,
              color: aldeciTheme.colors.textSecondary,
              textTransform: 'uppercase',
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: `0 0 ${aldeciTheme.spacing.sm} 0`,
            }}>
              Encrypted
            </h3>
            <div style={{
              fontSize: aldeciTheme.typography.fontSize.xxl,
              fontWeight: aldeciTheme.typography.fontWeight.bold,
              color: aldeciTheme.colors.textPrimary,
            }}>
              {evidenceBundles.filter(b => b.encrypted).length}
            </div>
          </div>
        </div>

        {/* Evidence Bundles List */}
        <div style={{
          background: aldeciTheme.colors.bgCard,
          borderRadius: aldeciTheme.borderRadius.lg,
          border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
          boxShadow: aldeciTheme.shadows.md,
          overflow: 'hidden',
        }}>
          <div style={{
            padding: aldeciTheme.spacing.md,
            borderBottom: `1px solid ${aldeciTheme.colors.borderPrimary}`,
            backgroundColor: 'rgba(0, 0, 0, 0.3)',
          }}>
            <h3 style={{
              fontSize: aldeciTheme.typography.fontSize.lg,
              fontWeight: aldeciTheme.typography.fontWeight.semibold,
              margin: 0,
            }}>
              Evidence Bundles
            </h3>
          </div>

          <div style={{
            maxHeight: '600px',
            overflowY: 'auto',
          }}>
            {evidenceBundles.map((bundle, index) => (
              <div
                key={bundle.run_id}
                style={{
                  padding: aldeciTheme.spacing.md,
                  borderBottom: index < evidenceBundles.length - 1 ? `1px solid ${aldeciTheme.colors.borderPrimary}` : 'none',
                }}
              >
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'start',
                  marginBottom: aldeciTheme.spacing.sm,
                }}>
                  <div style={{ flex: 1 }}>
                    <h4 style={{
                      fontSize: aldeciTheme.typography.fontSize.base,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      margin: 0,
                      color: aldeciTheme.colors.textPrimary,
                    }}>
                      {bundle.run_id}
                    </h4>
                    <div style={{
                      fontSize: aldeciTheme.typography.fontSize.sm,
                      color: aldeciTheme.colors.textSecondary,
                      marginTop: aldeciTheme.spacing.xs,
                    }}>
                      {formatDate(bundle.created_at)} • {formatBytes(bundle.size_bytes)}
                    </div>
                  </div>

                  <div style={{
                    display: 'flex',
                    gap: aldeciTheme.spacing.xs,
                    alignItems: 'center',
                  }}>
                    {bundle.encrypted && (
                      <span style={{
                        padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                        backgroundColor: 'rgba(16, 185, 129, 0.2)',
                        border: `1px solid ${aldeciTheme.colors.success}`,
                        borderRadius: aldeciTheme.borderRadius.sm,
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      }}>
                        🔒 Encrypted
                      </span>
                    )}
                    {bundle.compressed && (
                      <span style={{
                        padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                        backgroundColor: 'rgba(59, 130, 246, 0.2)',
                        border: `1px solid ${aldeciTheme.colors.info}`,
                        borderRadius: aldeciTheme.borderRadius.sm,
                        fontSize: aldeciTheme.typography.fontSize.xs,
                        fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      }}>
                        📦 Compressed
                      </span>
                    )}
                    <span style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: getRetentionBadgeColor(),
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                    }}>
                      {bundle.retention_days} days
                    </span>
                  </div>
                </div>

                {/* Sections */}
                <div style={{
                  display: 'flex',
                  gap: aldeciTheme.spacing.xs,
                  flexWrap: 'wrap',
                  marginBottom: aldeciTheme.spacing.sm,
                }}>
                  {bundle.sections.map(section => (
                    <span key={section} style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.sm}`,
                      backgroundColor: 'rgba(107, 90, 237, 0.2)',
                      border: `1px solid ${aldeciTheme.colors.primary}`,
                      borderRadius: aldeciTheme.borderRadius.sm,
                      fontSize: aldeciTheme.typography.fontSize.xs,
                      fontWeight: aldeciTheme.typography.fontWeight.medium,
                    }}>
                      {section}
                    </span>
                  ))}
                </div>

                {/* SHA256 */}
                <div style={{
                  padding: aldeciTheme.spacing.sm,
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: aldeciTheme.borderRadius.sm,
                  marginBottom: aldeciTheme.spacing.sm,
                }}>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textSecondary,
                    marginBottom: aldeciTheme.spacing.xs,
                  }}>
                    SHA256 Checksum
                  </div>
                  <div style={{
                    fontSize: aldeciTheme.typography.fontSize.xs,
                    color: aldeciTheme.colors.textPrimary,
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                  }}>
                    {bundle.sha256}
                  </div>
                </div>

                {/* Actions */}
                <div style={{
                  display: 'flex',
                  gap: aldeciTheme.spacing.sm,
                }}>
                  <button
                    onClick={() => viewManifest(bundle)}
                    style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.md}`,
                      backgroundColor: aldeciTheme.colors.primary,
                      border: 'none',
                      borderRadius: aldeciTheme.borderRadius.md,
                      color: aldeciTheme.colors.textPrimary,
                      fontSize: aldeciTheme.typography.fontSize.sm,
                      fontWeight: aldeciTheme.typography.fontWeight.semibold,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    View Manifest
                  </button>
                  <button
                    onClick={() => downloadBundle(bundle)}
                    style={{
                      padding: `${aldeciTheme.spacing.xs} ${aldeciTheme.spacing.md}`,
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                      border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
                      borderRadius: aldeciTheme.borderRadius.md,
                      color: aldeciTheme.colors.textPrimary,
                      fontSize: aldeciTheme.typography.fontSize.sm,
                      fontWeight: aldeciTheme.typography.fontWeight.medium,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    Download Bundle
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Manifest Modal */}
      {selectedBundle && (
        <div
          onClick={() => setSelectedBundle(null)}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 1000,
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: aldeciTheme.colors.bgCard,
              borderRadius: aldeciTheme.borderRadius.lg,
              border: `1px solid ${aldeciTheme.colors.borderPrimary}`,
              padding: aldeciTheme.spacing.lg,
              maxWidth: '800px',
              maxHeight: '80vh',
              overflowY: 'auto',
              boxShadow: aldeciTheme.shadows.lg,
            }}
          >
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: aldeciTheme.spacing.md,
            }}>
              <h2 style={{
                fontSize: aldeciTheme.typography.fontSize.xl,
                fontWeight: aldeciTheme.typography.fontWeight.bold,
                margin: 0,
              }}>
                Evidence Manifest
              </h2>
              <button
                onClick={() => setSelectedBundle(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: aldeciTheme.colors.textPrimary,
                  fontSize: aldeciTheme.typography.fontSize.xl,
                  cursor: 'pointer',
                  padding: aldeciTheme.spacing.xs,
                  lineHeight: 1,
                }}
              >
                ×
              </button>
            </div>

            <pre style={{
              padding: aldeciTheme.spacing.md,
              backgroundColor: 'rgba(0, 0, 0, 0.5)',
              borderRadius: aldeciTheme.borderRadius.md,
              fontSize: aldeciTheme.typography.fontSize.xs,
              color: aldeciTheme.colors.textPrimary,
              fontFamily: 'monospace',
              overflow: 'auto',
              lineHeight: 1.6,
            }}>
              {JSON.stringify(selectedBundle, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}

export default EvidenceTimeline
