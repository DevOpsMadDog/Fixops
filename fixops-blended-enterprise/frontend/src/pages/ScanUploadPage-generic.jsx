import React, { useState } from 'react'

function ScanUploadPage() {
  const [uploadState, setUploadState] = useState({
    file: null,
    serviceName: '',
    environment: 'production',
    scanType: '',
    isUploading: false,
    result: null,
    error: null,
    uploadProgress: 0
  })

  const supportedFormats = [
    { value: 'sarif', label: 'SARIF', desc: 'Static Analysis Results Interchange Format', icon: '🔍' },
    { value: 'sbom', label: 'SBOM', desc: 'Software Bill of Materials (CycloneDX)', icon: '📦' },
    { value: 'ibom', label: 'IBOM', desc: 'Infrastructure Bill of Materials', icon: '🏗️' },
    { value: 'csv', label: 'CSV', desc: 'Comma-Separated Values', icon: '📊' },
    { value: 'json', label: 'JSON', desc: 'JavaScript Object Notation', icon: '📋' }
  ]

  const handleFileChange = (event) => {
    const file = event.target.files[0]
    if (file) {
      // Validate file size (10MB limit)
      if (file.size > 10 * 1024 * 1024) {
        setUploadState(prev => ({
          ...prev,
          error: 'File size too large. Maximum 10MB allowed.',
          file: null
        }))
        return
      }
      
      // Validate file type based on selected format
      const validExtensions = {
        sarif: ['.sarif', '.json'],
        sbom: ['.json', '.xml'],
        ibom: ['.json', '.xml'],
        dast: ['.json', '.xml'],
        csv: ['.csv'],
        json: ['.json']
      }
      
      const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
      const validExts = validExtensions[uploadState.scanType] || ['.json']
      
      if (uploadState.scanType && !validExts.includes(fileExtension)) {
        setUploadState(prev => ({
          ...prev,
          error: `Invalid file type for ${uploadState.scanType.toUpperCase()}. Expected: ${validExts.join(', ')}`,
          file: null
        }))
        return
      }
      
      setUploadState(prev => ({
        ...prev,
        file,
        error: null,
        result: null
      }))
    }
  }

  const handleUpload = async () => {
    if (!uploadState.file || !uploadState.serviceName || !uploadState.scanType) {
      setUploadState(prev => ({
        ...prev,
        error: 'Please fill in all required fields and select a file'
      }))
      return
    }

    setUploadState(prev => ({ ...prev, isUploading: true, error: null, uploadProgress: 0 }))

    try {
      const formData = new FormData()
      formData.append('file', uploadState.file)
      formData.append('service_name', uploadState.serviceName)
      formData.append('environment', uploadState.environment)
      formData.append('scan_type', uploadState.scanType)

      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setUploadState(prev => ({
          ...prev,
          uploadProgress: Math.min(prev.uploadProgress + 10, 90)
        }))
      }, 200)

      const response = await fetch('/api/v1/scans/upload', {
        method: 'POST',
        body: formData,
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token') || 'demo-token'}`
        }
      })

      clearInterval(progressInterval)
      setUploadState(prev => ({ ...prev, uploadProgress: 100 }))

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || `Upload failed: ${response.statusText}`)
      }

      const result = await response.json()
      
      setUploadState(prev => ({
        ...prev,
        result: result.data,
        isUploading: false,
        file: null,
        serviceName: '',
        uploadProgress: 0
      }))

      // Reset file input
      const fileInput = document.getElementById('fileInput')
      if (fileInput) fileInput.value = ''

    } catch (error) {
      setUploadState(prev => ({
        ...prev,
        error: error.message,
        isUploading: false,
        uploadProgress: 0
      }))
    }
  }

  return (
    <div style={{
      padding: '3rem 2rem',
      maxWidth: '1200px',
      margin: '0 auto'
    }}>
      {/* Header */}
      <div style={{ marginBottom: '3rem', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '3rem',
          fontWeight: 'bold',
          color: '#1f2937',
          marginBottom: '0.75rem',
          letterSpacing: '-0.025em'
        }}>
          Security Scan Upload
        </h1>
        <p style={{ 
          color: '#6b7280', 
          fontSize: '1.25rem',
          maxWidth: '600px',
          margin: '0 auto',
          lineHeight: '1.6'
        }}>
          Upload and process security scan files through FixOps correlation engine
        </p>
      </div>

      {/* Upload Form */}
      <div style={{
        backgroundColor: 'white',
        padding: '3rem',
        borderRadius: '20px',
        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        border: '1px solid #e5e7eb',
        marginBottom: '2rem'
      }}>
        {/* File Format Selection */}
        <div style={{ marginBottom: '2rem' }}>
          <h3 style={{
            fontSize: '1.25rem',
            fontWeight: '700',
            color: '#1f2937',
            marginBottom: '1rem'
          }}>
            Select Scan Format
          </h3>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem'
          }}>
            {supportedFormats.map((format) => (
              <div
                key={format.value}
                onClick={() => setUploadState(prev => ({ ...prev, scanType: format.value, error: null }))}
                style={{
                  padding: '1.5rem',
                  borderRadius: '12px',
                  border: uploadState.scanType === format.value ? '2px solid #2563eb' : '2px solid #e5e7eb',
                  backgroundColor: uploadState.scanType === format.value ? '#f0f9ff' : 'white',
                  cursor: 'pointer',
                  textAlign: 'center',
                  transition: 'all 0.2s ease-in-out'
                }}
                onMouseEnter={(e) => {
                  if (uploadState.scanType !== format.value) {
                    e.currentTarget.style.backgroundColor = '#f9fafb'
                    e.currentTarget.style.borderColor = '#d1d5db'
                  }
                }}
                onMouseLeave={(e) => {
                  if (uploadState.scanType !== format.value) {
                    e.currentTarget.style.backgroundColor = 'white'
                    e.currentTarget.style.borderColor = '#e5e7eb'
                  }
                }}
              >
                <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>{format.icon}</div>
                <div style={{ fontSize: '1.125rem', fontWeight: '700', color: '#1f2937', marginBottom: '0.25rem' }}>
                  {format.label}
                </div>
                <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                  {format.desc}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Service Details */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '2rem',
          marginBottom: '2rem'
        }}>
          <div>
            <label style={{
              display: 'block',
              fontSize: '1rem',
              fontWeight: '600',
              color: '#374151',
              marginBottom: '0.5rem'
            }}>
              Service Name *
            </label>
            <input
              type="text"
              value={uploadState.serviceName}
              onChange={(e) => setUploadState(prev => ({ ...prev, serviceName: e.target.value, error: null }))}
              placeholder="e.g., payment-service, user-auth, api-gateway"
              style={{
                width: '100%',
                padding: '1rem',
                fontSize: '1rem',
                border: '2px solid #e5e7eb',
                borderRadius: '8px',
                outline: 'none',
                transition: 'border-color 0.2s ease-in-out'
              }}
              onFocus={(e) => e.target.style.borderColor = '#2563eb'}
              onBlur={(e) => e.target.style.borderColor = '#e5e7eb'}
            />
          </div>
          <div>
            <label style={{
              display: 'block',
              fontSize: '1rem',
              fontWeight: '600',
              color: '#374151',
              marginBottom: '0.5rem'
            }}>
              Environment
            </label>
            <select
              value={uploadState.environment}
              onChange={(e) => setUploadState(prev => ({ ...prev, environment: e.target.value }))}
              style={{
                width: '100%',
                padding: '1rem',
                fontSize: '1rem',
                border: '2px solid #e5e7eb',
                borderRadius: '8px',
                outline: 'none',
                backgroundColor: 'white'
              }}
            >
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="testing">Testing</option>
            </select>
          </div>
        </div>

        {/* File Upload */}
        <div style={{ marginBottom: '2rem' }}>
          <label style={{
            display: 'block',
            fontSize: '1rem',
            fontWeight: '600',
            color: '#374151',
            marginBottom: '0.5rem'
          }}>
            Security Scan File *
          </label>
          <div style={{
            border: '2px dashed #d1d5db',
            borderRadius: '12px',
            padding: '3rem',
            textAlign: 'center',
            backgroundColor: '#f9fafb',
            transition: 'all 0.2s ease-in-out'
          }}>
            <input
              id="fileInput"
              type="file"
              onChange={handleFileChange}
              accept=".json,.sarif,.csv,.xml"
              style={{ display: 'none' }}
            />
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📁</div>
            <div style={{ fontSize: '1.125rem', fontWeight: '600', color: '#1f2937', marginBottom: '0.5rem' }}>
              {uploadState.file ? uploadState.file.name : 'Drop your scan file here or click to browse'}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '1rem' }}>
              Supports SARIF, SBOM, IBOM, CSV, JSON (max 10MB)
            </div>
            <button
              onClick={() => document.getElementById('fileInput').click()}
              style={{
                padding: '0.75rem 2rem',
                backgroundColor: '#2563eb',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '1rem',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'background-color 0.2s ease-in-out'
              }}
              onMouseEnter={(e) => e.target.style.backgroundColor = '#1d4ed8'}
              onMouseLeave={(e) => e.target.style.backgroundColor = '#2563eb'}
            >
              Choose File
            </button>
          </div>
        </div>

        {/* Upload Progress */}
        {uploadState.isUploading && (
          <div style={{ marginBottom: '2rem' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '0.5rem'
            }}>
              <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>
                Upload Progress
              </span>
              <span style={{ fontSize: '0.875rem', fontWeight: '600', color: '#2563eb' }}>
                {uploadState.uploadProgress}%
              </span>
            </div>
            <div style={{
              width: '100%',
              height: '8px',
              backgroundColor: '#e5e7eb',
              borderRadius: '4px',
              overflow: 'hidden'
            }}>
              <div style={{
                width: `${uploadState.uploadProgress}%`,
                height: '100%',
                backgroundColor: '#2563eb',
                borderRadius: '4px',
                transition: 'width 0.3s ease-in-out'
              }}></div>
            </div>
          </div>
        )}

        {/* Upload Button */}
        <div style={{ textAlign: 'center' }}>
          <button
            onClick={handleUpload}
            disabled={uploadState.isUploading || !uploadState.file || !uploadState.serviceName || !uploadState.scanType}
            style={{
              padding: '1rem 3rem',
              backgroundColor: uploadState.isUploading || !uploadState.file || !uploadState.serviceName || !uploadState.scanType ? '#9ca3af' : '#16a34a',
              color: 'white',
              border: 'none',
              borderRadius: '12px',
              fontSize: '1.125rem',
              fontWeight: '700',
              cursor: uploadState.isUploading || !uploadState.file || !uploadState.serviceName || !uploadState.scanType ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.2s ease-in-out',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              margin: '0 auto'
            }}
          >
            {uploadState.isUploading ? (
              <>
                <div style={{
                  width: '20px',
                  height: '20px',
                  border: '2px solid transparent',
                  borderTop: '2px solid white',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }}></div>
                Processing...
              </>
            ) : (
              <>
                🚀 Process Scan File
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Display */}
      {uploadState.error && (
        <div style={{
          backgroundColor: '#fef2f2',
          border: '1px solid #fecaca',
          borderRadius: '12px',
          padding: '1.5rem',
          marginBottom: '2rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <span style={{ fontSize: '1.5rem', marginRight: '0.75rem' }}>❌</span>
            <div>
              <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#dc2626', margin: '0 0 0.25rem 0' }}>
                Upload Error
              </h4>
              <p style={{ fontSize: '0.875rem', color: '#b91c1c', margin: 0 }}>
                {uploadState.error}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Success Results */}
      {uploadState.result && (
        <div style={{
          backgroundColor: 'white',
          padding: '2.5rem',
          borderRadius: '16px',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid #e5e7eb'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2rem' }}>
            <div style={{
              width: '56px',
              height: '56px',
              backgroundColor: '#dcfce7',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '1rem'
            }}>
              <span style={{ fontSize: '1.75rem' }}>✅</span>
            </div>
            <div>
              <h3 style={{ 
                fontSize: '1.75rem', 
                fontWeight: '700', 
                color: '#1f2937', 
                margin: 0
              }}>
                Processing Complete
              </h3>
              <p style={{ fontSize: '1rem', color: '#6b7280', margin: 0 }}>
                Scan file successfully processed and analyzed
              </p>
            </div>
          </div>

          {/* Processing Results */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1.5rem',
            marginBottom: '2rem'
          }}>
            <div style={{
              padding: '1.5rem',
              backgroundColor: '#f0f9ff',
              borderRadius: '12px',
              border: '1px solid #bfdbfe',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#2563eb', marginBottom: '0.5rem' }}>
                {uploadState.result.findings_processed}
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                Findings Processed
              </div>
            </div>
            <div style={{
              padding: '1.5rem',
              backgroundColor: '#f0fdf4',
              borderRadius: '12px',
              border: '1px solid #bbf7d0',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#16a34a', marginBottom: '0.5rem' }}>
                {uploadState.result.correlations_found}
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                Correlations Found
              </div>
            </div>
            <div style={{
              padding: '1.5rem',
              backgroundColor: '#fef3c7',
              borderRadius: '12px',
              border: '1px solid #fed7aa',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#d97706', marginBottom: '0.5rem' }}>
                {uploadState.result.processing_time_ms}ms
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>
                Processing Time
              </div>
            </div>
          </div>

          {/* Upload Metadata */}
          <div style={{
            backgroundColor: '#f8fafc',
            padding: '1.5rem',
            borderRadius: '12px',
            border: '1px solid #e5e7eb'
          }}>
            <h4 style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', marginBottom: '1rem' }}>
              Upload Details
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Service:</span>
                <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>
                  {uploadState.result.service_name}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>File:</span>
                <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>
                  {uploadState.result.upload_metadata.filename}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Type:</span>
                <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937', textTransform: 'uppercase' }}>
                  {uploadState.result.upload_metadata.scan_type}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.875rem', color: '#6b7280', fontWeight: '600' }}>Size:</span>
                <div style={{ fontSize: '1rem', fontWeight: '700', color: '#1f2937' }}>
                  {Math.round(uploadState.result.upload_metadata.file_size_bytes / 1024)}KB
                </div>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ textAlign: 'center', marginTop: '2rem' }}>
            <button
              onClick={() => setUploadState(prev => ({ ...prev, result: null }))}
              style={{
                padding: '0.75rem 2rem',
                backgroundColor: '#6b7280',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '1rem',
                fontWeight: '600',
                cursor: 'pointer',
                marginRight: '1rem',
                transition: 'background-color 0.2s ease-in-out'
              }}
              onMouseEnter={(e) => e.target.style.backgroundColor = '#4b5563'}
              onMouseLeave={(e) => e.target.style.backgroundColor = '#6b7280'}
            >
              Upload Another File
            </button>
            <button
              onClick={() => window.location.href = '/developer'}
              style={{
                padding: '0.75rem 2rem',
                backgroundColor: '#2563eb',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '1rem',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'background-color 0.2s ease-in-out'
              }}
              onMouseEnter={(e) => e.target.style.backgroundColor = '#1d4ed8'}
              onMouseLeave={(e) => e.target.style.backgroundColor = '#2563eb'}
            >
              View Dashboard
            </button>
          </div>
        </div>
      )}

      {/* CSS Animation */}
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}

export default ScanUploadPage