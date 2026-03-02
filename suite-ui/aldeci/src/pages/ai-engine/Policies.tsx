import { useState, useCallback, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface PolicyRule {
  condition: string;
  action: string;
  severity?: string;
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  policy_type: string;
  enabled: boolean;
  rules?: PolicyRule[] | Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
  violations_count?: number;
  last_evaluated?: string;
}

interface ValidationResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
  coverage?: number;
}

const appleEase = [0.16, 1, 0.3, 1] as const;

const policyTypeColor = (type: string) => {
  switch (type?.toLowerCase()) {
    case 'security': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'compliance': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'quality': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'operational': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    case 'risk': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const policyTypeIcon = (type: string) => {
  switch (type?.toLowerCase()) {
    case 'security': return '🛡️';
    case 'compliance': return '📋';
    case 'quality': return '✨';
    case 'operational': return '⚙️';
    case 'risk': return '⚠️';
    default: return '📜';
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// Create Policy Dialog
// ═══════════════════════════════════════════════════════════════════════════

function CreatePolicyForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [policyType, setPolicyType] = useState('security');
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    if (!name.trim()) {
      toast.error('Policy name is required');
      return;
    }
    setCreating(true);
    try {
      await api.post('/api/v1/policies', {
        name: name.trim(),
        description: description.trim(),
        policy_type: policyType,
        rules: {},
      });
      toast.success(`Policy "${name}" created`);
      setName('');
      setDescription('');
      onCreated();
    } catch (err) {
      console.error('Create policy failed', err);
      toast.error('Failed to create policy');
    } finally {
      setCreating(false);
    }
  };

  return (
    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
      <CardHeader>
        <CardTitle className="text-lg text-gray-200">Create New Policy</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <label className="text-xs text-muted-foreground block mb-1.5">Policy Name</label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Critical CVE SLA"
            className="bg-gray-800/50 border-gray-700/50"
          />
        </div>
        <div>
          <label className="text-xs text-muted-foreground block mb-1.5">Description</label>
          <Textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe the policy purpose and scope..."
            className="bg-gray-800/50 border-gray-700/50 min-h-[80px]"
          />
        </div>
        <div>
          <label className="text-xs text-muted-foreground block mb-1.5">Policy Type</label>
          <div className="flex flex-wrap gap-2">
            {['security', 'compliance', 'quality', 'operational', 'risk'].map((t) => (
              <button
                key={t}
                onClick={() => setPolicyType(t)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
                  policyType === t
                    ? policyTypeColor(t)
                    : 'border-gray-700/30 bg-gray-800/20 text-gray-400 hover:bg-gray-800/40'
                }`}
              >
                {policyTypeIcon(t)} {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <Button
          onClick={handleCreate}
          disabled={creating || !name.trim()}
          className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white shadow-lg shadow-indigo-500/20"
        >
          {creating ? (
            <span className="flex items-center gap-2"><span className="animate-spin">⚙️</span> Creating...</span>
          ) : '+ Create Policy'}
        </Button>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Policy Card
// ═══════════════════════════════════════════════════════════════════════════

function PolicyCard({
  policy,
  index,
  onValidate,
  validating,
}: {
  policy: Policy;
  index: number;
  onValidate: (id: string) => void;
  validating: string | null;
}) {
  const rulesCount = Array.isArray(policy.rules) ? policy.rules.length : Object.keys(policy.rules || {}).length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, ease: appleEase }}
      className="border border-gray-700/30 rounded-lg bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-all p-4"
    >
      <div className="flex justify-between items-start gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <span className="text-lg">{policyTypeIcon(policy.policy_type)}</span>
            <span className="font-semibold text-gray-200">{policy.name}</span>
            <Badge variant="outline" className={policyTypeColor(policy.policy_type)}>
              {policy.policy_type}
            </Badge>
            <Badge
              variant="outline"
              className={policy.enabled
                ? 'bg-green-500/20 text-green-400 border-green-500/30'
                : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
              }
            >
              {policy.enabled ? '● Active' : '○ Inactive'}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">{policy.description || 'No description'}</p>
          <div className="flex gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
            <span>{rulesCount} rule{rulesCount !== 1 ? 's' : ''}</span>
            {policy.violations_count !== undefined && (
              <span className={policy.violations_count > 0 ? 'text-red-400' : 'text-green-400'}>
                {policy.violations_count} violation{policy.violations_count !== 1 ? 's' : ''}
              </span>
            )}
            {policy.created_at && (
              <span>Created: {new Date(policy.created_at).toLocaleDateString()}</span>
            )}
            {policy.last_evaluated && (
              <span>Last evaluated: {new Date(policy.last_evaluated).toLocaleString()}</span>
            )}
          </div>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button
            size="sm"
            variant="outline"
            onClick={() => onValidate(policy.id)}
            disabled={validating === policy.id}
            className="border-gray-600/50 text-gray-300 hover:bg-gray-800/50"
          >
            {validating === policy.id ? (
              <span className="flex items-center gap-1"><span className="animate-spin text-xs">⚙</span> Validating</span>
            ) : '✓ Validate'}
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════════

const Policies = () => {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [validating, setValidating] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/api/v1/policies');
      const data = res.data?.items || res.data || [];
      setPolicies(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Failed to fetch policies', err);
      toast.error('Failed to load policies');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const handleValidate = async (id: string) => {
    setValidating(id);
    toast.info('Validating policy...');
    try {
      const res = await api.post(`/api/v1/policies/${id}/validate`);
      const result = res.data as ValidationResult;
      setValidationResult(result);
      if (result.valid) {
        toast.success('Policy validated successfully');
      } else {
        toast.error(`Validation failed with ${result.errors?.length ?? 0} error(s)`);
      }
    } catch (err) {
      console.error('Validation failed', err);
      toast.error('Policy validation failed');
    } finally {
      setValidating(null);
    }
  };

  // Compute stats
  const activeCount = policies.filter(p => p.enabled).length;
  const totalViolations = policies.reduce((sum, p) => sum + (p.violations_count ?? 0), 0);
  const typeBreakdown: Record<string, number> = {};
  policies.forEach(p => { typeBreakdown[p.policy_type] = (typeBreakdown[p.policy_type] || 0) + 1; });

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex justify-between items-center"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-400 via-blue-400 to-cyan-400 bg-clip-text text-transparent">
            Policy Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Define, manage, and enforce security policies across your organization
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchPolicies} className="border-gray-600/50">
            ↻ Refresh
          </Button>
          <Button
            onClick={() => setShowCreate(!showCreate)}
            className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white shadow-lg shadow-indigo-500/20"
          >
            {showCreate ? '✕ Cancel' : '+ Create Policy'}
          </Button>
        </div>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Policies', value: policies.length, color: 'text-blue-400', icon: '📜' },
          { label: 'Active', value: activeCount, color: 'text-green-400', icon: '✅' },
          { label: 'Violations', value: totalViolations, color: totalViolations > 0 ? 'text-red-400' : 'text-green-400', icon: '⚠️' },
          { label: 'Types', value: Object.keys(typeBreakdown).length, color: 'text-purple-400', icon: '📋' },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05, ease: appleEase }}
          >
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-colors">
              <CardContent className="pt-4 pb-3 text-center">
                {loading ? (
                  <div className="animate-pulse">
                    <div className="h-8 bg-gray-700/30 rounded w-12 mx-auto mb-1" />
                    <div className="h-3 bg-gray-700/20 rounded w-16 mx-auto" />
                  </div>
                ) : (
                  <>
                    <div className="text-xs mb-0.5">{s.icon}</div>
                    <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{s.label}</div>
                  </>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Create Policy Form */}
      <AnimatePresence>
        {showCreate && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ ease: appleEase }}
          >
            <CreatePolicyForm onCreated={() => { fetchPolicies(); setShowCreate(false); }} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Validation Result */}
      <AnimatePresence>
        {validationResult && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            <Card className={`border-gray-700/30 backdrop-blur-md ${
              validationResult.valid
                ? 'bg-green-900/20 border-green-500/30'
                : 'bg-red-900/20 border-red-500/30'
            }`}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{validationResult.valid ? '✅' : '❌'}</span>
                    <div>
                      <p className={`font-medium ${validationResult.valid ? 'text-green-400' : 'text-red-400'}`}>
                        {validationResult.valid ? 'Policy is valid' : 'Validation failed'}
                      </p>
                      {validationResult.errors && validationResult.errors.length > 0 && (
                        <div className="text-sm text-red-300 mt-1">
                          {validationResult.errors.map((e, i) => <div key={i}>• {e}</div>)}
                        </div>
                      )}
                      {validationResult.warnings && validationResult.warnings.length > 0 && (
                        <div className="text-sm text-yellow-300 mt-1">
                          {validationResult.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
                        </div>
                      )}
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setValidationResult(null)}
                    className="text-gray-400"
                  >
                    ✕
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Policy List */}
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
        <CardHeader>
          <CardTitle className="text-lg text-gray-200">
            Security Policies ({policies.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4].map(i => (
                <div key={i} className="animate-pulse p-4 rounded-lg bg-gray-800/30 border border-gray-700/20">
                  <div className="h-5 bg-gray-700/30 rounded w-48 mb-2" />
                  <div className="h-3 bg-gray-700/20 rounded w-full mb-1" />
                  <div className="h-3 bg-gray-700/20 rounded w-2/3" />
                </div>
              ))}
            </div>
          ) : policies.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <div className="text-5xl mb-4">📜</div>
              <p className="text-lg mb-2">No policies defined</p>
              <p className="text-sm mb-4">Create your first security policy to enforce standards across your organization</p>
              <Button
                onClick={() => setShowCreate(true)}
                className="bg-gradient-to-r from-indigo-600 to-blue-600 text-white"
              >
                + Create First Policy
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {policies.map((policy, i) => (
                <PolicyCard
                  key={policy.id}
                  policy={policy}
                  index={i}
                  onValidate={handleValidate}
                  validating={validating}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Policy Type Breakdown */}
      {Object.keys(typeBreakdown).length > 0 && (
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader>
            <CardTitle className="text-sm text-gray-300">Policy Type Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4 flex-wrap">
              {Object.entries(typeBreakdown).sort(([, a], [, b]) => b - a).map(([type, count], i) => (
                <motion.div
                  key={type}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: i * 0.05, ease: appleEase }}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${policyTypeColor(type)}`}
                >
                  <span>{policyTypeIcon(type)}</span>
                  <span className="text-sm font-medium capitalize">{type}</span>
                  <span className="text-xs opacity-80">({count})</span>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default Policies;
