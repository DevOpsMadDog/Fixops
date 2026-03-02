import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, ArrowLeft, Home } from 'lucide-react';
import { Button } from '../components/ui/button';

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="flex items-center justify-center min-h-[70vh]">
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ type: 'spring', stiffness: 200, damping: 25 }}
        className="text-center max-w-md mx-auto space-y-6"
      >
        {/* Animated Shield Icon */}
        <motion.div
          animate={{ y: [0, -8, 0] }}
          transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
          className="inline-flex"
        >
          <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 flex items-center justify-center">
            <Shield className="w-12 h-12 text-indigo-400" />
          </div>
        </motion.div>

        {/* Error Text */}
        <div className="space-y-2">
          <h1 className="text-6xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
            404
          </h1>
          <h2 className="text-xl font-semibold text-gray-200">
            Page Not Found
          </h2>
          <p className="text-gray-400 text-sm leading-relaxed">
            The security operation you&apos;re looking for doesn&apos;t exist or has been moved.
            Use the navigation sidebar or press <kbd className="px-1.5 py-0.5 bg-gray-800 border border-gray-600 rounded text-[10px] font-mono">⌘K</kbd> to search.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-center gap-3">
          <Button
            variant="outline"
            onClick={() => navigate(-1)}
            className="border-gray-600/50 hover:border-indigo-500/50"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Go Back
          </Button>
          <Button
            onClick={() => navigate('/')}
            className="bg-indigo-600 hover:bg-indigo-500 text-white"
          >
            <Home className="w-4 h-4 mr-2" />
            Dashboard
          </Button>
        </div>

        {/* Quick Links */}
        <div className="pt-4 border-t border-gray-700/30">
          <p className="text-xs text-gray-500 mb-3">Quick navigation:</p>
          <div className="flex flex-wrap justify-center gap-2">
            {[
              { label: 'Scanners', path: '/discover/scanners' },
              { label: 'Brain Pipeline', path: '/core/brain-pipeline' },
              { label: 'MPTE Console', path: '/attack/mpte' },
              { label: 'AutoFix', path: '/protect/autofix' },
              { label: 'Evidence', path: '/evidence/bundles' },
            ].map(link => (
              <button
                key={link.path}
                onClick={() => navigate(link.path)}
                className="px-3 py-1.5 text-xs bg-gray-800/60 border border-gray-700/40 rounded-full text-gray-300 hover:text-white hover:border-indigo-500/50 transition-colors"
              >
                {link.label}
              </button>
            ))}
          </div>
        </div>
      </motion.div>
    </div>
  );
}
