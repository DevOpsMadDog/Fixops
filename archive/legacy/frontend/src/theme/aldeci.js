/**
 * Aldeci Brand Theme Configuration
 * Based on https://devops-ai-website-mc67od8m.devinapps.com/product/aldeci
 */

export const aldeciTheme = {
  colors: {
    primary: '#6B5AED',        // Purple accent for interactive elements
    secondary: '#0F172A',      // Dark slate for backgrounds
    accent: '#3b82f6',         // Blue accent for highlights
    success: '#10b981',        // Green for success states
    warning: '#f59e0b',        // Amber for warnings
    danger: '#dc2626',         // Red for critical/errors
    info: '#3b82f6',           // Blue for info
    
    critical: '#dc2626',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#3b82f6',
    
    bgPrimary: 'radial-gradient(circle at top, #1e293b 0%, #0f172a 50%, #000000 100%)',
    bgCard: 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%)',
    bgCardAlt: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.6) 100%)',
    
    textPrimary: '#ffffff',
    textSecondary: '#94a3b8',
    textMuted: '#64748b',
    
    borderPrimary: 'rgba(255, 255, 255, 0.1)',
    borderAccent: 'rgba(107, 90, 237, 0.3)',
  },
  
  spacing: {
    xs: '0.25rem',
    sm: '0.5rem',
    md: '1rem',
    lg: '1.5rem',
    xl: '2rem',
    xxl: '3rem',
  },
  
  borderRadius: {
    sm: '4px',
    md: '6px',
    lg: '8px',
    xl: '12px',
  },
  
  shadows: {
    sm: '0 1px 3px rgba(0, 0, 0, 0.2)',
    md: '0 2px 10px rgba(0, 0, 0, 0.3)',
    lg: '0 4px 20px rgba(0, 0, 0, 0.4)',
  },
  
  typography: {
    fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
    fontSize: {
      xs: '0.625rem',
      sm: '0.75rem',
      base: '0.875rem',
      md: '1rem',
      lg: '1.25rem',
      xl: '1.5rem',
      xxl: '2rem',
    },
    fontWeight: {
      normal: '400',
      medium: '500',
      semibold: '600',
      bold: '700',
    },
  },
  
  graph: {
    node: {
      service: {
        backgroundColor: '#6B5AED',
        borderColor: '#8b7aff',
        textColor: '#ffffff',
      },
      component: {
        backgroundColor: '#3b82f6',
        borderColor: '#60a5fa',
        textColor: '#ffffff',
      },
      cve: {
        critical: { backgroundColor: '#dc2626', borderColor: '#ef4444' },
        high: { backgroundColor: '#f97316', borderColor: '#fb923c' },
        medium: { backgroundColor: '#f59e0b', borderColor: '#fbbf24' },
        low: { backgroundColor: '#3b82f6', borderColor: '#60a5fa' },
      },
      finding: {
        error: { backgroundColor: '#dc2626', borderColor: '#ef4444' },
        warning: { backgroundColor: '#f59e0b', borderColor: '#fbbf24' },
        info: { backgroundColor: '#3b82f6', borderColor: '#60a5fa' },
      },
    },
    edge: {
      default: '#475569',
      highlighted: '#6B5AED',
      critical: '#dc2626',
    },
  },
}

export default aldeciTheme
