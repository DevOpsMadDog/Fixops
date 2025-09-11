import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  Code, 
  Shield, 
  Layers, 
  Server, 
  AlertTriangle, 
  Settings, 
  FileText,
  ChevronLeft,
  ChevronRight,
  Target,
  Zap
} from 'lucide-react';

const Sidebar = ({ open, setOpen }) => {
  const navigation = [
    {
      name: 'Developer View',
      href: '/developer',
      icon: Code,
      description: 'Security findings & fixes'
    },
    {
      name: 'CISO Executive',
      href: '/ciso',
      icon: Shield,
      description: 'Risk metrics & compliance'
    },
    {
      name: 'Architecture',
      href: '/architect',
      icon: Layers,
      description: 'Service topology & threats'
    },
    {
      name: 'Services',
      href: '/services',
      icon: Server,
      description: 'Service registry'
    },
    {
      name: 'Security Findings',
      href: '/findings',
      icon: AlertTriangle,
      description: 'Cross-scanner correlation'
    },
    {
      name: 'Correlated Cases',
      href: '/cases',
      icon: Target,
      description: 'Unified security cases'
    },
    {
      name: 'Policy Engine',
      href: '/policies',
      icon: Settings,
      description: 'NIST SSDF policies'
    }
  ];

  return (
    <div className={`fixed inset-y-0 left-0 z-50 ${open ? 'w-64' : 'w-16'} bg-slate-900 transition-all duration-300 ease-in-out`}>
      <div className="flex h-full flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          {open && (
            <div className="flex items-center space-x-2">
              <div className="flex items-center justify-center w-8 h-8 bg-blue-600 rounded-lg">
                <Zap className="w-5 h-5 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">FixOps</h2>
                <p className="text-xs text-slate-400">DevSecOps Control</p>
              </div>
            </div>
          )}
          <button
            onClick={() => setOpen(!open)}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            {open ? <ChevronLeft className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <ul className="space-y-2">
            {navigation.map((item) => (
              <li key={item.name}>
                <NavLink
                  to={item.href}
                  className={({ isActive }) =>
                    `group flex items-center rounded-lg p-3 text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                    }`
                  }
                >
                  <item.icon className={`${open ? 'mr-3' : 'mx-auto'} h-5 w-5 flex-shrink-0`} />
                  {open && (
                    <div className="flex-1">
                      <div className="text-sm font-medium">{item.name}</div>
                      <div className="text-xs text-slate-400 group-hover:text-slate-300">
                        {item.description}
                      </div>
                    </div>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        {/* Footer */}
        {open && (
          <div className="p-4 border-t border-slate-700">
            <div className="text-xs text-slate-400">
              <div className="font-semibold text-slate-300 mb-1">NIST SSDF Compliant</div>
              <div>Real-time policy enforcement</div>
              <div>67% noise reduction active</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Sidebar;