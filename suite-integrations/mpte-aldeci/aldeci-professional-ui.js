/**
 * ALdeci Professional Security Intelligence Platform
 * 
 * Modern, intuitive UI that integrates the Intelligent Security Engine
 * with a professional dashboard, workflow visualization, and real-time monitoring.
 */

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        apiBase: 'http://localhost:8000/api/v1',
        mindsdbBase: 'http://localhost:47334',
        refreshInterval: 5000,
        theme: 'dark',
        version: '2.0.0'
    };

    // Theme styles
    const THEMES = {
        dark: {
            bg: '#0d1117',
            bgSecondary: '#161b22',
            bgTertiary: '#21262d',
            border: '#30363d',
            text: '#e6edf3',
            textSecondary: '#8b949e',
            accent: '#58a6ff',
            accentGreen: '#3fb950',
            accentRed: '#f85149',
            accentOrange: '#d29922',
            accentPurple: '#a371f7',
            gradient: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
        }
    };

    const T = THEMES[CONFIG.theme];

    // State management
    const state = {
        currentView: 'dashboard',
        sessions: [],
        activeScan: null,
        findings: [],
        metrics: {},
        engineStatus: 'idle',
        mindsdbStatus: 'checking',
        notifications: [],
        expandedPanel: null
    };

    // Inject comprehensive styles
    function injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

            /* Reset and base */
            .aldeci-pro * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }

            /* Main container */
            .aldeci-pro-container {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: ${T.bg};
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                color: ${T.text};
                display: flex;
                flex-direction: column;
                z-index: 99999;
                overflow: hidden;
            }

            /* Header */
            .aldeci-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 16px 24px;
                background: ${T.bgSecondary};
                border-bottom: 1px solid ${T.border};
                flex-shrink: 0;
            }

            .aldeci-logo {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .aldeci-logo-icon {
                width: 36px;
                height: 36px;
                background: ${T.gradient};
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 18px;
            }

            .aldeci-logo-text {
                font-size: 20px;
                font-weight: 600;
                background: ${T.gradient};
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }

            .aldeci-logo-subtitle {
                font-size: 11px;
                color: ${T.textSecondary};
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            /* Status indicators */
            .aldeci-status-bar {
                display: flex;
                align-items: center;
                gap: 20px;
            }

            .aldeci-status-item {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 13px;
                color: ${T.textSecondary};
            }

            .aldeci-status-dot {
                width: 8px;
                height: 8px;
                border-radius: 50%;
                animation: pulse 2s infinite;
            }

            .aldeci-status-dot.active { background: ${T.accentGreen}; }
            .aldeci-status-dot.warning { background: ${T.accentOrange}; }
            .aldeci-status-dot.error { background: ${T.accentRed}; }
            .aldeci-status-dot.idle { background: ${T.textSecondary}; }

            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }

            /* Main layout */
            .aldeci-main {
                display: flex;
                flex: 1;
                overflow: hidden;
            }

            /* Sidebar navigation */
            .aldeci-sidebar {
                width: 72px;
                background: ${T.bgSecondary};
                border-right: 1px solid ${T.border};
                display: flex;
                flex-direction: column;
                padding: 16px 0;
                gap: 8px;
                align-items: center;
            }

            .aldeci-nav-item {
                width: 48px;
                height: 48px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 12px;
                cursor: pointer;
                transition: all 0.2s;
                color: ${T.textSecondary};
                position: relative;
            }

            .aldeci-nav-item:hover {
                background: ${T.bgTertiary};
                color: ${T.text};
            }

            .aldeci-nav-item.active {
                background: rgba(88, 166, 255, 0.15);
                color: ${T.accent};
            }

            .aldeci-nav-item svg {
                width: 22px;
                height: 22px;
            }

            .aldeci-nav-tooltip {
                position: absolute;
                left: 60px;
                background: ${T.bgTertiary};
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 12px;
                white-space: nowrap;
                opacity: 0;
                pointer-events: none;
                transition: opacity 0.2s;
                z-index: 100;
            }

            .aldeci-nav-item:hover .aldeci-nav-tooltip {
                opacity: 1;
            }

            .aldeci-nav-divider {
                width: 32px;
                height: 1px;
                background: ${T.border};
                margin: 8px 0;
            }

            /* Content area */
            .aldeci-content {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }

            /* Tab bar */
            .aldeci-tabs {
                display: flex;
                gap: 4px;
                padding: 12px 24px;
                background: ${T.bgSecondary};
                border-bottom: 1px solid ${T.border};
                overflow-x: auto;
            }

            .aldeci-tab {
                padding: 8px 16px;
                background: transparent;
                border: 1px solid transparent;
                border-radius: 8px;
                color: ${T.textSecondary};
                font-size: 13px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s;
                white-space: nowrap;
            }

            .aldeci-tab:hover {
                background: ${T.bgTertiary};
                color: ${T.text};
            }

            .aldeci-tab.active {
                background: rgba(88, 166, 255, 0.1);
                border-color: ${T.accent};
                color: ${T.accent};
            }

            /* Dashboard grid */
            .aldeci-dashboard {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                grid-template-rows: auto auto 1fr;
                gap: 20px;
                padding: 24px;
                overflow-y: auto;
            }

            /* Cards */
            .aldeci-card {
                background: ${T.bgSecondary};
                border: 1px solid ${T.border};
                border-radius: 12px;
                overflow: hidden;
            }

            .aldeci-card-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 16px 20px;
                border-bottom: 1px solid ${T.border};
            }

            .aldeci-card-title {
                font-size: 14px;
                font-weight: 600;
                color: ${T.text};
            }

            .aldeci-card-body {
                padding: 20px;
            }

            /* Metric cards */
            .aldeci-metric-card {
                background: ${T.bgSecondary};
                border: 1px solid ${T.border};
                border-radius: 12px;
                padding: 20px;
            }

            .aldeci-metric-label {
                font-size: 12px;
                color: ${T.textSecondary};
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 8px;
            }

            .aldeci-metric-value {
                font-size: 32px;
                font-weight: 700;
                color: ${T.text};
                line-height: 1;
            }

            .aldeci-metric-trend {
                display: flex;
                align-items: center;
                gap: 4px;
                margin-top: 8px;
                font-size: 12px;
            }

            .aldeci-metric-trend.up { color: ${T.accentRed}; }
            .aldeci-metric-trend.down { color: ${T.accentGreen}; }

            /* Risk gauge */
            .aldeci-gauge {
                position: relative;
                width: 120px;
                height: 120px;
                margin: 0 auto;
            }

            .aldeci-gauge-circle {
                width: 100%;
                height: 100%;
                border-radius: 50%;
                background: conic-gradient(
                    ${T.accentRed} 0deg,
                    ${T.accentOrange} 120deg,
                    ${T.accentGreen} 240deg,
                    ${T.accentGreen} 360deg
                );
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .aldeci-gauge-inner {
                width: 80%;
                height: 80%;
                background: ${T.bgSecondary};
                border-radius: 50%;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
            }

            .aldeci-gauge-value {
                font-size: 28px;
                font-weight: 700;
                color: ${T.text};
            }

            .aldeci-gauge-label {
                font-size: 11px;
                color: ${T.textSecondary};
            }

            /* Progress bars */
            .aldeci-progress {
                height: 6px;
                background: ${T.bgTertiary};
                border-radius: 3px;
                overflow: hidden;
            }

            .aldeci-progress-bar {
                height: 100%;
                border-radius: 3px;
                transition: width 0.3s ease;
            }

            /* Buttons */
            .aldeci-btn {
                padding: 10px 20px;
                border-radius: 8px;
                border: none;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }

            .aldeci-btn-primary {
                background: ${T.gradient};
                color: white;
            }

            .aldeci-btn-primary:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
            }

            .aldeci-btn-secondary {
                background: ${T.bgTertiary};
                color: ${T.text};
                border: 1px solid ${T.border};
            }

            .aldeci-btn-danger {
                background: rgba(248, 81, 73, 0.15);
                color: ${T.accentRed};
                border: 1px solid rgba(248, 81, 73, 0.3);
            }

            /* Input fields */
            .aldeci-input {
                width: 100%;
                padding: 12px 16px;
                background: ${T.bg};
                border: 1px solid ${T.border};
                border-radius: 8px;
                color: ${T.text};
                font-size: 14px;
                font-family: inherit;
                transition: border-color 0.2s;
            }

            .aldeci-input:focus {
                outline: none;
                border-color: ${T.accent};
            }

            .aldeci-input::placeholder {
                color: ${T.textSecondary};
            }

            /* Tables */
            .aldeci-table {
                width: 100%;
                border-collapse: collapse;
            }

            .aldeci-table th,
            .aldeci-table td {
                padding: 12px 16px;
                text-align: left;
                border-bottom: 1px solid ${T.border};
            }

            .aldeci-table th {
                font-size: 12px;
                font-weight: 600;
                color: ${T.textSecondary};
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .aldeci-table tr:hover {
                background: ${T.bgTertiary};
            }

            /* Badges */
            .aldeci-badge {
                padding: 4px 10px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 500;
            }

            .aldeci-badge-critical { background: rgba(248, 81, 73, 0.2); color: ${T.accentRed}; }
            .aldeci-badge-high { background: rgba(210, 153, 34, 0.2); color: ${T.accentOrange}; }
            .aldeci-badge-medium { background: rgba(88, 166, 255, 0.2); color: ${T.accent}; }
            .aldeci-badge-low { background: rgba(63, 185, 80, 0.2); color: ${T.accentGreen}; }

            /* Timeline */
            .aldeci-timeline {
                position: relative;
                padding-left: 24px;
            }

            .aldeci-timeline::before {
                content: '';
                position: absolute;
                left: 7px;
                top: 0;
                bottom: 0;
                width: 2px;
                background: ${T.border};
            }

            .aldeci-timeline-item {
                position: relative;
                padding-bottom: 20px;
            }

            .aldeci-timeline-item::before {
                content: '';
                position: absolute;
                left: -20px;
                top: 4px;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: ${T.bgTertiary};
                border: 2px solid ${T.accent};
            }

            .aldeci-timeline-item.completed::before {
                background: ${T.accentGreen};
                border-color: ${T.accentGreen};
            }

            .aldeci-timeline-item.active::before {
                background: ${T.accent};
                border-color: ${T.accent};
                animation: pulse 2s infinite;
            }

            /* Attack flow visualization */
            .aldeci-attack-flow {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 20px;
                overflow-x: auto;
            }

            .aldeci-flow-node {
                min-width: 140px;
                padding: 16px;
                background: ${T.bgTertiary};
                border: 2px solid ${T.border};
                border-radius: 12px;
                text-align: center;
                position: relative;
            }

            .aldeci-flow-node.active {
                border-color: ${T.accent};
                box-shadow: 0 0 20px rgba(88, 166, 255, 0.3);
            }

            .aldeci-flow-node.success {
                border-color: ${T.accentGreen};
            }

            .aldeci-flow-connector {
                width: 40px;
                height: 2px;
                background: ${T.border};
                position: relative;
            }

            .aldeci-flow-connector::after {
                content: '';
                position: absolute;
                right: 0;
                top: -4px;
                border: 5px solid transparent;
                border-left-color: ${T.border};
            }

            /* Scan panel */
            .aldeci-scan-panel {
                grid-column: span 4;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
            }

            /* Console output */
            .aldeci-console {
                background: ${T.bg};
                border-radius: 8px;
                padding: 16px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                max-height: 300px;
                overflow-y: auto;
            }

            .aldeci-console-line {
                padding: 2px 0;
                color: ${T.textSecondary};
            }

            .aldeci-console-line.success { color: ${T.accentGreen}; }
            .aldeci-console-line.error { color: ${T.accentRed}; }
            .aldeci-console-line.warning { color: ${T.accentOrange}; }
            .aldeci-console-line.info { color: ${T.accent}; }

            /* Modal */
            .aldeci-modal-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 100000;
            }

            .aldeci-modal {
                background: ${T.bgSecondary};
                border: 1px solid ${T.border};
                border-radius: 16px;
                width: 90%;
                max-width: 600px;
                max-height: 80vh;
                overflow: hidden;
            }

            .aldeci-modal-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 20px 24px;
                border-bottom: 1px solid ${T.border};
            }

            .aldeci-modal-body {
                padding: 24px;
                overflow-y: auto;
            }

            .aldeci-modal-footer {
                display: flex;
                justify-content: flex-end;
                gap: 12px;
                padding: 16px 24px;
                border-top: 1px solid ${T.border};
            }

            /* Close button */
            .aldeci-close-btn {
                position: absolute;
                top: 16px;
                right: 16px;
                width: 32px;
                height: 32px;
                border-radius: 8px;
                background: ${T.bgTertiary};
                border: 1px solid ${T.border};
                color: ${T.textSecondary};
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s;
            }

            .aldeci-close-btn:hover {
                background: ${T.accentRed};
                color: white;
                border-color: ${T.accentRed};
            }

            /* Minimize button */
            .aldeci-minimize-btn {
                position: fixed;
                bottom: 20px;
                right: 20px;
                width: 56px;
                height: 56px;
                border-radius: 28px;
                background: ${T.gradient};
                border: none;
                color: white;
                cursor: pointer;
                box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
                display: none;
                align-items: center;
                justify-content: center;
                z-index: 99998;
                transition: transform 0.2s;
            }

            .aldeci-minimize-btn:hover {
                transform: scale(1.1);
            }

            .aldeci-minimize-btn svg {
                width: 24px;
                height: 24px;
            }

            /* Animations */
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            .aldeci-animate-in {
                animation: slideIn 0.3s ease;
            }

            /* Scrollbar styling */
            .aldeci-pro-container ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }

            .aldeci-pro-container ::-webkit-scrollbar-track {
                background: ${T.bg};
            }

            .aldeci-pro-container ::-webkit-scrollbar-thumb {
                background: ${T.bgTertiary};
                border-radius: 4px;
            }

            .aldeci-pro-container ::-webkit-scrollbar-thumb:hover {
                background: ${T.textSecondary};
            }

            /* Loading spinner */
            .aldeci-spinner {
                width: 20px;
                height: 20px;
                border: 2px solid ${T.bgTertiary};
                border-top-color: ${T.accent};
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            /* Severity chart */
            .aldeci-severity-chart {
                display: flex;
                gap: 16px;
                align-items: flex-end;
                height: 100px;
                padding: 20px;
            }

            .aldeci-severity-bar {
                flex: 1;
                border-radius: 4px 4px 0 0;
                position: relative;
                transition: height 0.3s;
            }

            .aldeci-severity-bar::after {
                content: attr(data-count);
                position: absolute;
                bottom: 100%;
                left: 50%;
                transform: translateX(-50%);
                font-size: 12px;
                font-weight: 600;
                margin-bottom: 4px;
            }

            .aldeci-hidden {
                display: none !important;
            }
        `;
        document.head.appendChild(style);
    }

    // Icons
    const ICONS = {
        dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
        scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>',
        findings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
        compliance: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>',
        intelligence: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 110 20 10 10 0 010-20zM12 6v6l4 2"/></svg>',
        settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>',
        close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
        stop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg>',
        check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
        alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        brain: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5a3 3 0 10-5.997.125 4 4 0 00-2.526 5.77 4 4 0 00.556 6.588A4 4 0 1012 18"/><path d="M12 5a3 3 0 115.997.125 4 4 0 012.526 5.77 4 4 0 01-.556 6.588A4 4 0 1112 18"/><path d="M12 5v13M15 9l-3 3-3-3"/></svg>',
        target: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
        maximize: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 00-2 2v3m18 0V5a2 2 0 00-2-2h-3m0 18h3a2 2 0 002-2v-3M3 16v3a2 2 0 002 2h3"/></svg>',
        minimize: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14h6v6M20 10h-6V4M14 10l7-7M3 21l7-7"/></svg>'
    };

    // Build the main UI
    function buildUI() {
        const container = document.createElement('div');
        container.className = 'aldeci-pro aldeci-pro-container';
        container.id = 'aldeci-pro-ui';
        
        container.innerHTML = `
            <!-- Header -->
            <header class="aldeci-header">
                <div class="aldeci-logo">
                    <div class="aldeci-logo-icon">A</div>
                    <div>
                        <div class="aldeci-logo-text">ALdeci</div>
                        <div class="aldeci-logo-subtitle">Intelligent Security Platform</div>
                    </div>
                </div>
                <div class="aldeci-status-bar">
                    <div class="aldeci-status-item">
                        <span class="aldeci-status-dot" id="engine-status-dot"></span>
                        <span>Engine: <span id="engine-status-text">Idle</span></span>
                    </div>
                    <div class="aldeci-status-item">
                        <span class="aldeci-status-dot" id="mindsdb-status-dot"></span>
                        <span>MindsDB: <span id="mindsdb-status-text">Checking...</span></span>
                    </div>
                    <div class="aldeci-status-item">
                        <span class="aldeci-status-dot active" id="api-status-dot"></span>
                        <span>API: <span id="api-status-text">Connected</span></span>
                    </div>
                    <button class="aldeci-close-btn" id="aldeci-minimize" title="Minimize">
                        ${ICONS.minimize}
                    </button>
                </div>
            </header>

            <!-- Main content -->
            <main class="aldeci-main">
                <!-- Sidebar -->
                <nav class="aldeci-sidebar">
                    <div class="aldeci-nav-item active" data-view="dashboard">
                        ${ICONS.dashboard}
                        <span class="aldeci-nav-tooltip">Dashboard</span>
                    </div>
                    <div class="aldeci-nav-item" data-view="scan">
                        ${ICONS.target}
                        <span class="aldeci-nav-tooltip">Intelligent Scan</span>
                    </div>
                    <div class="aldeci-nav-item" data-view="findings">
                        ${ICONS.findings}
                        <span class="aldeci-nav-tooltip">Findings</span>
                    </div>
                    <div class="aldeci-nav-divider"></div>
                    <div class="aldeci-nav-item" data-view="intelligence">
                        ${ICONS.brain}
                        <span class="aldeci-nav-tooltip">AI Intelligence</span>
                    </div>
                    <div class="aldeci-nav-item" data-view="compliance">
                        ${ICONS.compliance}
                        <span class="aldeci-nav-tooltip">Compliance</span>
                    </div>
                    <div class="aldeci-nav-divider"></div>
                    <div class="aldeci-nav-item" data-view="settings">
                        ${ICONS.settings}
                        <span class="aldeci-nav-tooltip">Settings</span>
                    </div>
                </nav>

                <!-- Content -->
                <div class="aldeci-content">
                    ${buildDashboardView()}
                    ${buildScanView()}
                    ${buildFindingsView()}
                    ${buildIntelligenceView()}
                    ${buildComplianceView()}
                    ${buildSettingsView()}
                </div>
            </main>
        `;

        document.body.appendChild(container);

        // Create minimize button
        const minimizeBtn = document.createElement('button');
        minimizeBtn.className = 'aldeci-minimize-btn';
        minimizeBtn.id = 'aldeci-restore';
        minimizeBtn.innerHTML = ICONS.shield;
        document.body.appendChild(minimizeBtn);

        // Event listeners
        setupEventListeners();
        
        // Initial data fetch
        fetchDashboardData();
        checkServicesStatus();
    }

    function buildDashboardView() {
        return `
            <div id="view-dashboard" class="aldeci-dashboard aldeci-animate-in">
                <!-- Metrics row -->
                <div class="aldeci-metric-card">
                    <div class="aldeci-metric-label">Active Scans</div>
                    <div class="aldeci-metric-value" id="metric-active-scans">0</div>
                    <div class="aldeci-metric-trend down">
                        <span>↓</span> 2 from yesterday
                    </div>
                </div>
                <div class="aldeci-metric-card">
                    <div class="aldeci-metric-label">Critical Findings</div>
                    <div class="aldeci-metric-value" id="metric-critical" style="color: ${T.accentRed}">12</div>
                    <div class="aldeci-metric-trend up">
                        <span>↑</span> 3 new today
                    </div>
                </div>
                <div class="aldeci-metric-card">
                    <div class="aldeci-metric-label">CVEs Validated</div>
                    <div class="aldeci-metric-value" id="metric-cves">847</div>
                    <div class="aldeci-metric-trend down">
                        <span>↓</span> 89% remediated
                    </div>
                </div>
                <div class="aldeci-metric-card">
                    <div class="aldeci-metric-label">Compliance Score</div>
                    <div class="aldeci-metric-value" id="metric-compliance" style="color: ${T.accentGreen}">94%</div>
                    <div class="aldeci-metric-trend down">
                        <span>↑</span> +2% this week
                    </div>
                </div>

                <!-- Risk overview -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Risk Overview</span>
                        <button class="aldeci-btn aldeci-btn-secondary" onclick="AldeciUI.refreshDashboard()">Refresh</button>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: flex; gap: 40px; align-items: center;">
                            <div class="aldeci-gauge">
                                <div class="aldeci-gauge-circle">
                                    <div class="aldeci-gauge-inner">
                                        <div class="aldeci-gauge-value" id="gauge-risk-score">72</div>
                                        <div class="aldeci-gauge-label">Risk Score</div>
                                    </div>
                                </div>
                            </div>
                            <div style="flex: 1;">
                                <div class="aldeci-severity-chart">
                                    <div class="aldeci-severity-bar" style="height: 90%; background: ${T.accentRed};" data-count="12"></div>
                                    <div class="aldeci-severity-bar" style="height: 60%; background: ${T.accentOrange};" data-count="28"></div>
                                    <div class="aldeci-severity-bar" style="height: 80%; background: ${T.accent};" data-count="45"></div>
                                    <div class="aldeci-severity-bar" style="height: 40%; background: ${T.accentGreen};" data-count="67"></div>
                                </div>
                                <div style="display: flex; justify-content: space-around; font-size: 11px; color: ${T.textSecondary}; margin-top: 8px;">
                                    <span>Critical</span>
                                    <span>High</span>
                                    <span>Medium</span>
                                    <span>Low</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Quick actions -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Quick Actions</span>
                    </div>
                    <div class="aldeci-card-body" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
                        <button class="aldeci-btn aldeci-btn-primary" onclick="AldeciUI.startQuickScan()">
                            ${ICONS.play} Start Intelligent Scan
                        </button>
                        <button class="aldeci-btn aldeci-btn-secondary" onclick="AldeciUI.showView('findings')">
                            ${ICONS.findings} Review Findings
                        </button>
                        <button class="aldeci-btn aldeci-btn-secondary" onclick="AldeciUI.runComplianceCheck()">
                            ${ICONS.compliance} Run Compliance Check
                        </button>
                        <button class="aldeci-btn aldeci-btn-secondary" onclick="AldeciUI.viewThreatIntel()">
                            ${ICONS.brain} Threat Intelligence
                        </button>
                    </div>
                </div>

                <!-- Recent activity -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Recent Activity</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div class="aldeci-timeline" id="activity-timeline">
                            <div class="aldeci-timeline-item completed">
                                <div style="font-weight: 500;">CVE-2024-21762 validated</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">2 minutes ago • Fortinet vulnerability confirmed exploitable</div>
                            </div>
                            <div class="aldeci-timeline-item completed">
                                <div style="font-weight: 500;">Intelligent scan completed</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">15 minutes ago • 3 critical findings</div>
                            </div>
                            <div class="aldeci-timeline-item active">
                                <div style="font-weight: 500;">ML model updating</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">In progress • Processing threat intelligence</div>
                            </div>
                            <div class="aldeci-timeline-item">
                                <div style="font-weight: 500;">Compliance report generated</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">1 hour ago • PCI-DSS v4.0</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- MITRE mapping -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">MITRE ATT&CK Coverage</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div id="mitre-heatmap" style="display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px;">
                            ${buildMitreHeatmap()}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function buildMitreHeatmap() {
        const tactics = ['Recon', 'Resource', 'Initial', 'Execution', 'Persist', 'Priv Esc', 'Defense'];
        return tactics.map(t => `
            <div style="text-align: center; padding: 12px; background: rgba(88, 166, 255, ${0.1 + Math.random() * 0.4}); border-radius: 6px;">
                <div style="font-size: 18px; font-weight: 700;">${Math.floor(Math.random() * 20)}</div>
                <div style="font-size: 10px; color: ${T.textSecondary};">${t}</div>
            </div>
        `).join('');
    }

    function buildScanView() {
        return `
            <div id="view-scan" class="aldeci-dashboard aldeci-hidden">
                <!-- Scan configuration -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Intelligent Security Scan</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: flex; flex-direction: column; gap: 16px;">
                            <div>
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">Target</label>
                                <input type="text" class="aldeci-input" id="scan-target" placeholder="https://target.example.com or IP address">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">CVEs (comma separated)</label>
                                <input type="text" class="aldeci-input" id="scan-cves" placeholder="CVE-2024-21762, CVE-2024-1234">
                            </div>
                            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                                <div>
                                    <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">Scan Type</label>
                                    <select class="aldeci-input" id="scan-type">
                                        <option value="passive">Passive (Read-only)</option>
                                        <option value="guided">Guided (AI-assisted)</option>
                                        <option value="autonomous">Autonomous</option>
                                        <option value="adversarial">Red Team Simulation</option>
                                    </select>
                                </div>
                                <div>
                                    <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">Intelligence Level</label>
                                    <select class="aldeci-input" id="scan-intelligence">
                                        <option value="standard">Standard</option>
                                        <option value="enhanced">Enhanced (ML)</option>
                                        <option value="adversarial">Adversarial AI</option>
                                    </select>
                                </div>
                                <div>
                                    <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">Compliance Framework</label>
                                    <select class="aldeci-input" id="scan-compliance">
                                        <option value="">None</option>
                                        <option value="pci-dss">PCI-DSS</option>
                                        <option value="soc2">SOC 2</option>
                                        <option value="hipaa">HIPAA</option>
                                        <option value="nist">NIST CSF</option>
                                    </select>
                                </div>
                            </div>
                            <div style="display: flex; gap: 12px; margin-top: 8px;">
                                <button class="aldeci-btn aldeci-btn-primary" onclick="AldeciUI.startScan()">
                                    ${ICONS.play} Start Intelligent Scan
                                </button>
                                <button class="aldeci-btn aldeci-btn-secondary" onclick="AldeciUI.loadTemplate()">
                                    Load Template
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Attack flow preview -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">AI Attack Plan Preview</span>
                    </div>
                    <div class="aldeci-attack-flow" id="attack-flow">
                        <div class="aldeci-flow-node">
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-bottom: 4px;">PHASE 1</div>
                            <div style="font-weight: 600;">Reconnaissance</div>
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-top: 4px;">Port scan, service enumeration</div>
                        </div>
                        <div class="aldeci-flow-connector"></div>
                        <div class="aldeci-flow-node">
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-bottom: 4px;">PHASE 2</div>
                            <div style="font-weight: 600;">CVE Validation</div>
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-top: 4px;">Vulnerability testing</div>
                        </div>
                        <div class="aldeci-flow-connector"></div>
                        <div class="aldeci-flow-node">
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-bottom: 4px;">PHASE 3</div>
                            <div style="font-weight: 600;">Exploitation</div>
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-top: 4px;">Proof of concept</div>
                        </div>
                        <div class="aldeci-flow-connector"></div>
                        <div class="aldeci-flow-node">
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-bottom: 4px;">PHASE 4</div>
                            <div style="font-weight: 600;">Impact Assessment</div>
                            <div style="font-size: 11px; color: ${T.textSecondary}; margin-top: 4px;">Business impact analysis</div>
                        </div>
                    </div>
                </div>

                <!-- Console output -->
                <div class="aldeci-card" style="grid-column: span 4;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Execution Console</span>
                        <div style="display: flex; gap: 8px;">
                            <button class="aldeci-btn aldeci-btn-danger aldeci-hidden" id="stop-scan-btn" onclick="AldeciUI.stopScan()">
                                ${ICONS.stop} Stop
                            </button>
                            <button class="aldeci-btn aldeci-btn-secondary" onclick="AldeciUI.clearConsole()">Clear</button>
                        </div>
                    </div>
                    <div class="aldeci-console" id="scan-console">
                        <div class="aldeci-console-line info">[INFO] ALdeci Intelligent Security Engine ready</div>
                        <div class="aldeci-console-line info">[INFO] MindsDB ML layer connected</div>
                        <div class="aldeci-console-line">[INFO] Waiting for scan configuration...</div>
                    </div>
                </div>
            </div>
        `;
    }

    function buildFindingsView() {
        return `
            <div id="view-findings" class="aldeci-dashboard aldeci-hidden">
                <!-- Filters -->
                <div class="aldeci-card" style="grid-column: span 4;">
                    <div class="aldeci-card-body" style="display: flex; gap: 16px; align-items: center;">
                        <input type="text" class="aldeci-input" placeholder="Search findings..." style="max-width: 300px;">
                        <select class="aldeci-input" style="max-width: 150px;">
                            <option value="">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                        <select class="aldeci-input" style="max-width: 150px;">
                            <option value="">All Sources</option>
                            <option value="scan">Intelligent Scan</option>
                            <option value="import">Import</option>
                            <option value="continuous">Continuous</option>
                        </select>
                        <div style="flex: 1;"></div>
                        <button class="aldeci-btn aldeci-btn-primary">Export Report</button>
                    </div>
                </div>

                <!-- Findings table -->
                <div class="aldeci-card" style="grid-column: span 4;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Vulnerability Findings</span>
                        <span style="color: ${T.textSecondary}; font-size: 13px;">152 total findings</span>
                    </div>
                    <div style="overflow-x: auto;">
                        <table class="aldeci-table">
                            <thead>
                                <tr>
                                    <th>CVE ID</th>
                                    <th>Severity</th>
                                    <th>EPSS</th>
                                    <th>KEV</th>
                                    <th>Target</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="findings-table-body">
                                <tr>
                                    <td><strong>CVE-2024-21762</strong></td>
                                    <td><span class="aldeci-badge aldeci-badge-critical">Critical</span></td>
                                    <td>0.976</td>
                                    <td><span style="color: ${T.accentRed};">●</span> Yes</td>
                                    <td>fw-prod-01.example.com</td>
                                    <td><span class="aldeci-badge" style="background: rgba(88, 166, 255, 0.2); color: ${T.accent};">Validated</span></td>
                                    <td>
                                        <button class="aldeci-btn aldeci-btn-secondary" style="padding: 6px 12px; font-size: 12px;">Details</button>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>CVE-2024-1709</strong></td>
                                    <td><span class="aldeci-badge aldeci-badge-critical">Critical</span></td>
                                    <td>0.892</td>
                                    <td><span style="color: ${T.accentRed};">●</span> Yes</td>
                                    <td>connect.example.com</td>
                                    <td><span class="aldeci-badge aldeci-badge-high">Exploitable</span></td>
                                    <td>
                                        <button class="aldeci-btn aldeci-btn-secondary" style="padding: 6px 12px; font-size: 12px;">Details</button>
                                    </td>
                                </tr>
                                <tr>
                                    <td><strong>CVE-2024-22024</strong></td>
                                    <td><span class="aldeci-badge aldeci-badge-high">High</span></td>
                                    <td>0.654</td>
                                    <td><span style="color: ${T.textSecondary};">○</span> No</td>
                                    <td>vpn.example.com</td>
                                    <td><span class="aldeci-badge aldeci-badge-medium">Investigating</span></td>
                                    <td>
                                        <button class="aldeci-btn aldeci-btn-secondary" style="padding: 6px 12px; font-size: 12px;">Details</button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }

    function buildIntelligenceView() {
        return `
            <div id="view-intelligence" class="aldeci-dashboard aldeci-hidden">
                <!-- AI Insights -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">AI Intelligence Hub</span>
                        <span class="aldeci-status-dot active"></span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
                            <div style="padding: 16px; background: ${T.bg}; border-radius: 8px;">
                                <div style="font-size: 24px; font-weight: 700; color: ${T.accentPurple};">4</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">AI Models Active</div>
                            </div>
                            <div style="padding: 16px; background: ${T.bg}; border-radius: 8px;">
                                <div style="font-size: 24px; font-weight: 700; color: ${T.accent};">89%</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">Consensus Rate</div>
                            </div>
                            <div style="padding: 16px; background: ${T.bg}; border-radius: 8px;">
                                <div style="font-size: 24px; font-weight: 700; color: ${T.accentGreen};">1,247</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">Predictions Made</div>
                            </div>
                            <div style="padding: 16px; background: ${T.bg}; border-radius: 8px;">
                                <div style="font-size: 24px; font-weight: 700; color: ${T.accentOrange};">0.94</div>
                                <div style="font-size: 12px; color: ${T.textSecondary};">Model Accuracy</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ML Models -->
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">MindsDB ML Models</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: flex; flex-direction: column; gap: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: ${T.bg}; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 500;">exploit_success_predictor</div>
                                    <div style="font-size: 12px; color: ${T.textSecondary};">Lightwood • R² Score: 0.91</div>
                                </div>
                                <span class="aldeci-badge aldeci-badge-low">Active</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: ${T.bg}; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 500;">attack_path_predictor</div>
                                    <div style="font-size: 12px; color: ${T.textSecondary};">Lightwood • Accuracy: 0.87</div>
                                </div>
                                <span class="aldeci-badge aldeci-badge-low">Active</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: ${T.bg}; border-radius: 8px;">
                                <div>
                                    <div style="font-weight: 500;">threat_actor_classifier</div>
                                    <div style="font-size: 12px; color: ${T.textSecondary};">GPT-4 • Knowledge Base</div>
                                </div>
                                <span class="aldeci-badge aldeci-badge-low">Active</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- LLM Consensus -->
                <div class="aldeci-card" style="grid-column: span 4;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Multi-LLM Consensus Engine</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px;">
                            <div style="text-align: center; padding: 20px; background: ${T.bg}; border-radius: 12px; border: 2px solid ${T.border};">
                                <div style="font-size: 28px; margin-bottom: 8px;">🧠</div>
                                <div style="font-weight: 600;">GPT-4</div>
                                <div style="font-size: 12px; color: ${T.textSecondary}; margin-bottom: 8px;">Strategic Lead</div>
                                <div style="font-size: 20px; font-weight: 700; color: ${T.accentGreen};">0.25</div>
                                <div style="font-size: 11px; color: ${T.textSecondary};">Weight</div>
                            </div>
                            <div style="text-align: center; padding: 20px; background: ${T.bg}; border-radius: 12px; border: 2px solid ${T.border};">
                                <div style="font-size: 28px; margin-bottom: 8px;">🤖</div>
                                <div style="font-weight: 600;">Claude</div>
                                <div style="font-size: 12px; color: ${T.textSecondary}; margin-bottom: 8px;">Developer</div>
                                <div style="font-size: 20px; font-weight: 700; color: ${T.accent};">0.40</div>
                                <div style="font-size: 11px; color: ${T.textSecondary};">Weight</div>
                            </div>
                            <div style="text-align: center; padding: 20px; background: ${T.bg}; border-radius: 12px; border: 2px solid ${T.border};">
                                <div style="font-size: 28px; margin-bottom: 8px;">💎</div>
                                <div style="font-weight: 600;">Gemini</div>
                                <div style="font-size: 12px; color: ${T.textSecondary}; margin-bottom: 8px;">Architect</div>
                                <div style="font-size: 20px; font-weight: 700; color: ${T.accentPurple};">0.35</div>
                                <div style="font-size: 11px; color: ${T.textSecondary};">Weight</div>
                            </div>
                            <div style="text-align: center; padding: 20px; background: ${T.bg}; border-radius: 12px; border: 2px solid rgba(248, 81, 73, 0.3);">
                                <div style="font-size: 28px; margin-bottom: 8px;">🛡️</div>
                                <div style="font-weight: 600;">Sentinel</div>
                                <div style="font-size: 12px; color: ${T.textSecondary}; margin-bottom: 8px;">Security Override</div>
                                <div style="font-size: 20px; font-weight: 700; color: ${T.accentRed};">VETO</div>
                                <div style="font-size: 11px; color: ${T.textSecondary};">Authority</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function buildComplianceView() {
        return `
            <div id="view-compliance" class="aldeci-dashboard aldeci-hidden">
                <div class="aldeci-card" style="grid-column: span 4;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Compliance Frameworks</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px;">
                            <div style="padding: 20px; background: ${T.bg}; border-radius: 12px; text-align: center;">
                                <div style="font-size: 36px; font-weight: 700; color: ${T.accentGreen};">94%</div>
                                <div style="font-size: 14px; font-weight: 600; margin: 8px 0;">PCI-DSS v4.0</div>
                                <div class="aldeci-progress" style="margin-top: 12px;">
                                    <div class="aldeci-progress-bar" style="width: 94%; background: ${T.accentGreen};"></div>
                                </div>
                            </div>
                            <div style="padding: 20px; background: ${T.bg}; border-radius: 12px; text-align: center;">
                                <div style="font-size: 36px; font-weight: 700; color: ${T.accent};">87%</div>
                                <div style="font-size: 14px; font-weight: 600; margin: 8px 0;">SOC 2 Type II</div>
                                <div class="aldeci-progress" style="margin-top: 12px;">
                                    <div class="aldeci-progress-bar" style="width: 87%; background: ${T.accent};"></div>
                                </div>
                            </div>
                            <div style="padding: 20px; background: ${T.bg}; border-radius: 12px; text-align: center;">
                                <div style="font-size: 36px; font-weight: 700; color: ${T.accentOrange};">76%</div>
                                <div style="font-size: 14px; font-weight: 600; margin: 8px 0;">HIPAA</div>
                                <div class="aldeci-progress" style="margin-top: 12px;">
                                    <div class="aldeci-progress-bar" style="width: 76%; background: ${T.accentOrange};"></div>
                                </div>
                            </div>
                            <div style="padding: 20px; background: ${T.bg}; border-radius: 12px; text-align: center;">
                                <div style="font-size: 36px; font-weight: 700; color: ${T.accentGreen};">91%</div>
                                <div style="font-size: 14px; font-weight: 600; margin: 8px 0;">NIST CSF</div>
                                <div class="aldeci-progress" style="margin-top: 12px;">
                                    <div class="aldeci-progress-bar" style="width: 91%; background: ${T.accentGreen};"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="aldeci-card" style="grid-column: span 4;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Compliance Gaps</span>
                    </div>
                    <div style="overflow-x: auto;">
                        <table class="aldeci-table">
                            <thead>
                                <tr>
                                    <th>Framework</th>
                                    <th>Control</th>
                                    <th>Finding</th>
                                    <th>Impact</th>
                                    <th>Remediation</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>PCI-DSS</td>
                                    <td>6.2</td>
                                    <td>Unpatched critical vulnerabilities</td>
                                    <td><span class="aldeci-badge aldeci-badge-critical">Critical</span></td>
                                    <td>Apply patches within 30 days</td>
                                </tr>
                                <tr>
                                    <td>SOC 2</td>
                                    <td>CC6.1</td>
                                    <td>Insufficient access logging</td>
                                    <td><span class="aldeci-badge aldeci-badge-high">High</span></td>
                                    <td>Enable comprehensive audit logs</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }

    function buildSettingsView() {
        return `
            <div id="view-settings" class="aldeci-dashboard aldeci-hidden">
                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Engine Configuration</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: flex; flex-direction: column; gap: 16px;">
                            <div>
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">API Endpoint</label>
                                <input type="text" class="aldeci-input" value="${CONFIG.apiBase}" id="setting-api">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">MindsDB Endpoint</label>
                                <input type="text" class="aldeci-input" value="${CONFIG.mindsdbBase}" id="setting-mindsdb">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: ${T.textSecondary};">Consensus Threshold</label>
                                <input type="range" min="0.5" max="1" step="0.05" value="0.85" style="width: 100%;">
                            </div>
                            <button class="aldeci-btn aldeci-btn-primary" onclick="AldeciUI.saveSettings()">Save Settings</button>
                        </div>
                    </div>
                </div>

                <div class="aldeci-card" style="grid-column: span 2;">
                    <div class="aldeci-card-header">
                        <span class="aldeci-card-title">Guardrails</span>
                    </div>
                    <div class="aldeci-card-body">
                        <div style="display: flex; flex-direction: column; gap: 12px;">
                            <label style="display: flex; align-items: center; gap: 12px; cursor: pointer;">
                                <input type="checkbox" checked> Auto-stop on detection
                            </label>
                            <label style="display: flex; align-items: center; gap: 12px; cursor: pointer;">
                                <input type="checkbox" checked> Require approval for privilege escalation
                            </label>
                            <label style="display: flex; align-items: center; gap: 12px; cursor: pointer;">
                                <input type="checkbox" checked> Evidence collection enabled
                            </label>
                            <label style="display: flex; align-items: center; gap: 12px; cursor: pointer;">
                                <input type="checkbox" checked> Block destructive actions
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Event listeners
    function setupEventListeners() {
        // Navigation
        document.querySelectorAll('.aldeci-nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const view = item.dataset.view;
                if (view) {
                    showView(view);
                    document.querySelectorAll('.aldeci-nav-item').forEach(n => n.classList.remove('active'));
                    item.classList.add('active');
                }
            });
        });

        // Minimize/restore
        document.getElementById('aldeci-minimize').addEventListener('click', () => {
            document.getElementById('aldeci-pro-ui').classList.add('aldeci-hidden');
            document.getElementById('aldeci-restore').style.display = 'flex';
        });

        document.getElementById('aldeci-restore').addEventListener('click', () => {
            document.getElementById('aldeci-pro-ui').classList.remove('aldeci-hidden');
            document.getElementById('aldeci-restore').style.display = 'none';
        });
    }

    function showView(viewId) {
        document.querySelectorAll('.aldeci-content > div').forEach(view => {
            view.classList.add('aldeci-hidden');
        });
        const view = document.getElementById(`view-${viewId}`);
        if (view) {
            view.classList.remove('aldeci-hidden');
            view.classList.add('aldeci-animate-in');
        }
        state.currentView = viewId;
    }

    // API functions
    async function fetchDashboardData() {
        try {
            const response = await fetch(`${CONFIG.apiBase}/intake/dashboard`);
            if (response.ok) {
                const data = await response.json();
                updateDashboard(data);
            }
        } catch (error) {
            console.log('Dashboard fetch error:', error);
        }
    }

    async function checkServicesStatus() {
        // Check API
        try {
            const apiResponse = await fetch(`${CONFIG.apiBase}/health`);
            updateStatus('api', apiResponse.ok ? 'active' : 'error');
        } catch {
            updateStatus('api', 'error');
        }

        // Check MindsDB
        try {
            const mindsdbResponse = await fetch(`${CONFIG.mindsdbBase}/api/status`);
            updateStatus('mindsdb', mindsdbResponse.ok ? 'active' : 'warning');
        } catch {
            updateStatus('mindsdb', 'idle');
        }
    }

    function updateStatus(service, status) {
        const dot = document.getElementById(`${service}-status-dot`);
        const text = document.getElementById(`${service}-status-text`);
        
        if (dot) {
            dot.className = `aldeci-status-dot ${status}`;
        }
        if (text) {
            const statusMap = {
                'active': 'Connected',
                'warning': 'Degraded',
                'error': 'Disconnected',
                'idle': 'Not Started'
            };
            text.textContent = statusMap[status] || status;
        }
    }

    function updateDashboard(data) {
        // Update metrics
        if (data.metrics) {
            const activeScans = document.getElementById('metric-active-scans');
            if (activeScans) activeScans.textContent = data.metrics.active_scans || 0;
        }
    }

    function appendToConsole(message, type = 'info') {
        const console = document.getElementById('scan-console');
        if (console) {
            const line = document.createElement('div');
            line.className = `aldeci-console-line ${type}`;
            const timestamp = new Date().toLocaleTimeString();
            line.textContent = `[${timestamp}] ${message}`;
            console.appendChild(line);
            console.scrollTop = console.scrollHeight;
        }
    }

    // Public API
    window.AldeciUI = {
        showView,
        
        startQuickScan: () => {
            showView('scan');
            document.querySelectorAll('.aldeci-nav-item').forEach(n => n.classList.remove('active'));
            document.querySelector('[data-view="scan"]').classList.add('active');
        },

        startScan: async () => {
            const target = document.getElementById('scan-target').value;
            const cves = document.getElementById('scan-cves').value;
            const scanType = document.getElementById('scan-type').value;

            if (!target) {
                appendToConsole('Error: Target is required', 'error');
                return;
            }

            appendToConsole(`Starting ${scanType} scan on ${target}...`, 'info');
            document.getElementById('stop-scan-btn').classList.remove('aldeci-hidden');

            // Animate attack flow
            const nodes = document.querySelectorAll('.aldeci-flow-node');
            for (let i = 0; i < nodes.length; i++) {
                await new Promise(r => setTimeout(r, 2000));
                nodes[i].classList.add('active');
                appendToConsole(`Phase ${i + 1} in progress...`, 'info');
            }

            try {
                const response = await fetch(`${CONFIG.apiBase}/pentest/intelligent-scan`, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer demo-token'
                    },
                    body: JSON.stringify({
                        target,
                        cve_ids: cves.split(',').map(c => c.trim()).filter(Boolean),
                        scan_type: scanType
                    })
                });

                if (response.ok) {
                    const result = await response.json();
                    appendToConsole('Scan completed successfully!', 'success');
                    nodes.forEach(n => n.classList.replace('active', 'success'));
                } else {
                    appendToConsole('Scan completed with warnings', 'warning');
                }
            } catch (error) {
                appendToConsole(`Scan error: ${error.message}`, 'error');
            }

            document.getElementById('stop-scan-btn').classList.add('aldeci-hidden');
        },

        stopScan: () => {
            appendToConsole('Scan stopped by user', 'warning');
            document.getElementById('stop-scan-btn').classList.add('aldeci-hidden');
            document.querySelectorAll('.aldeci-flow-node').forEach(n => n.classList.remove('active'));
        },

        clearConsole: () => {
            document.getElementById('scan-console').innerHTML = 
                '<div class="aldeci-console-line info">[INFO] Console cleared</div>';
        },

        refreshDashboard: () => {
            fetchDashboardData();
            checkServicesStatus();
        },

        runComplianceCheck: async () => {
            showView('compliance');
        },

        viewThreatIntel: () => {
            showView('intelligence');
        },

        loadTemplate: () => {
            document.getElementById('scan-target').value = 'https://demo-target.example.com';
            document.getElementById('scan-cves').value = 'CVE-2024-21762, CVE-2024-1709';
            appendToConsole('Template loaded', 'info');
        },

        saveSettings: () => {
            CONFIG.apiBase = document.getElementById('setting-api').value;
            CONFIG.mindsdbBase = document.getElementById('setting-mindsdb').value;
            appendToConsole('Settings saved', 'success');
        }
    };

    // Initialize
    function init() {
        // Only inject if not already present
        if (document.getElementById('aldeci-pro-ui')) return;
        
        // Hide the original PentAGI root element
        document.body.classList.add('aldeci-active');
        const root = document.getElementById('root');
        if (root) {
            root.style.display = 'none';
        }
        
        injectStyles();
        buildUI();
        
        // Periodic refresh
        setInterval(() => {
            if (state.currentView === 'dashboard') {
                checkServicesStatus();
            }
        }, CONFIG.refreshInterval);
        
        console.log('ALdeci Professional UI v' + CONFIG.version + ' loaded');
    }

    // Wait for DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
