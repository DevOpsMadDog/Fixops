import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ClipboardList, Play, CheckCircle2, AlertTriangle, FileText, Save,
  Eye, Code, Plus, Trash2, ChevronRight, Loader2,
  Shield, Zap, Settings, ArrowRight, Copy, Download,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs';
import { nerveCenterApi } from '../../lib/api';
import { toast } from 'sonner';

const STEP_TYPES = [
  { value: 'policy_check', label: 'Policy Check', icon: Shield, color: 'text-blue-400' },
  { value: 'evidence_assert', label: 'Evidence Assert', icon: CheckCircle2, color: 'text-green-400' },
  { value: 'micro_pentest', label: 'Micro Pentest', icon: Zap, color: 'text-red-400' },
  { value: 'adapter_call', label: 'Adapter Call', icon: ArrowRight, color: 'text-purple-400' },
  { value: 'conditional', label: 'Conditional', icon: ChevronRight, color: 'text-yellow-400' },
  { value: 'parallel', label: 'Parallel', icon: Copy, color: 'text-cyan-400' },
];

const ADAPTERS = ['jira', 'slack', 'confluence', 'github', 'email', 'webhook'];
const FRAMEWORKS = ['SOC2', 'ISO27001', 'PCI_DSS', 'GDPR', 'NIST_SSDF', 'HIPAA', 'FedRAMP'];
const KINDS = ['Playbook', 'CompliancePack', 'TestPack', 'MitigationPack'];

const DEFAULT_YAML = `apiVersion: fixops.io/v1
kind: Playbook
metadata:
  name: my-playbook
  version: 1.0.0
  description: Automated vulnerability response
  author: Security Team
  tags: [security, automation]
  compliance_frameworks: [SOC2]
  ssdlc_stages: [deploy, operate]
spec:
  inputs:
    severity_threshold:
      type: string
      default: high
  conditions:
    - field: finding.severity
      operator: gte
      value: "{{ inputs.severity_threshold }}"
  steps:
    - name: check-policy
      type: policy_check
      policy: critical-vuln-policy
      on_failure: halt
    - name: create-ticket
      type: adapter_call
      adapter: jira
      action: create_issue
      inputs:
        project: SEC
        summary: "Vulnerability: {{ finding.cve_id }}"
        priority: High
  outputs:
    - name: ticket_id
      from: create-ticket.result.key
`;

export default function PlaybookEditor() {

  const [activeTab, setActiveTab] = useState('editor');
  const [yamlContent, setYamlContent] = useState(DEFAULT_YAML);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<any>(null);
  const [showStepBuilder, setShowStepBuilder] = useState(false);

  // Fetch playbooks
  const { data: playbooksData, isLoading } = useQuery({
    queryKey: ['nerve-center-playbooks'],
    queryFn: nerveCenterApi.getPlaybooks,
  });

  // Validate mutation
  const validateMutation = useMutation({
    mutationFn: async () => {
      // Parse YAML to object (simplified — in production use js-yaml)
      const parsed = simpleYamlParse(yamlContent);
      return nerveCenterApi.validatePlaybook(parsed);
    },
    onSuccess: (data) => {
      setValidationResult(data);
      if (data.valid) {
        toast.success('Playbook is valid!');
      } else {
        toast.error(`Validation failed: ${data.errors?.length || 0} error(s)`);
      }
    },
    onError: () => toast.error('Validation request failed'),
  });

  // Execute mutation
  const executeMutation = useMutation({
    mutationFn: ({ id, dryRun }: { id: string; dryRun: boolean }) =>
      nerveCenterApi.executePlaybook(id, dryRun),
    onSuccess: (data) => {
      toast.success(data.dry_run ? 'Dry run complete — no changes made' : `Playbook executing: ${data.execution_id}`);
    },
    onError: () => toast.error('Execution failed'),
  });

  const playbooks = playbooksData?.playbooks || [];

  // Simple YAML-to-object parser for validation (extracts top-level keys)
  function simpleYamlParse(yaml: string): Record<string, any> {
    const obj: Record<string, any> = {};
    const lines = yaml.split('\n');
    let currentKey = '';
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z_]+):/);
      if (match) {
        currentKey = match[1];
        const value = line.slice(match[0].length).trim();
        if (value) obj[currentKey] = value;
        else obj[currentKey] = {};
      } else if (currentKey && line.startsWith('  ')) {
        const subMatch = line.trim().match(/^([a-zA-Z_]+):\s*(.+)/);
        if (subMatch && typeof obj[currentKey] === 'object') {
          obj[currentKey][subMatch[1]] = subMatch[2];
        }
      }
    }
    return obj;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <ClipboardList className="w-8 h-8 text-primary" /> Playbook Editor
          </h1>
          <p className="text-muted-foreground mt-1">Create, validate, and execute security playbooks with YAML or visual builder</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => validateMutation.mutate()} disabled={validateMutation.isPending}>
            {validateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <CheckCircle2 className="w-4 h-4 mr-1" />} Validate
          </Button>
          <Button variant="outline" size="sm"><Download className="w-4 h-4 mr-1" /> Export</Button>
          <Button size="sm"><Save className="w-4 h-4 mr-1" /> Save</Button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Playbook List Sidebar */}
        <div className="col-span-3">
          <Card className="glass-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Playbooks</CardTitle>
              <CardDescription className="text-xs">{playbooks.length} available</CardDescription>
            </CardHeader>
            <CardContent className="space-y-1">
              {isLoading ? (
                <div className="flex justify-center py-4"><Loader2 className="w-5 h-5 animate-spin" /></div>
              ) : playbooks.map((pb: any) => (
                <button key={pb.id} onClick={() => setSelectedPlaybook(pb.id)}
                  className={`w-full text-left p-2 rounded-lg border transition-colors text-sm ${selectedPlaybook === pb.id ? 'border-primary bg-primary/10' : 'border-border/50 hover:bg-accent/30'}`}>
                  <div className="flex items-center justify-between">
                    <span className="font-medium truncate">{pb.name}</span>
                    <Badge variant="outline" className="text-[9px] shrink-0">{pb.kind}</Badge>
                  </div>
                  <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                    <span>v{pb.version}</span>
                    <span>•</span>
                    <span>{pb.steps} steps</span>
                    <span>•</span>
                    <span className={pb.status === 'active' ? 'text-green-400' : 'text-yellow-400'}>{pb.status}</span>
                  </div>
                  {pb.frameworks?.length > 0 && (
                    <div className="flex gap-1 mt-1">
                      {pb.frameworks.map((f: string) => (
                        <Badge key={f} variant="outline" className="text-[8px] px-1 py-0 h-3">{f}</Badge>
                      ))}
                    </div>
                  )}
                </button>
              ))}
              {/* Quick actions for selected playbook */}
              {selectedPlaybook && (
                <div className="flex gap-1 mt-2 pt-2 border-t border-border/50">
                  <Button size="sm" variant="outline" className="flex-1 text-xs h-7" onClick={() => executeMutation.mutate({ id: selectedPlaybook, dryRun: true })}>
                    <Eye className="w-3 h-3 mr-1" /> Dry Run
                  </Button>
                  <Button size="sm" className="flex-1 text-xs h-7" onClick={() => executeMutation.mutate({ id: selectedPlaybook, dryRun: false })}>
                    <Play className="w-3 h-3 mr-1" /> Execute
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Editor Area */}
        <div className="col-span-9">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="mb-4">
              <TabsTrigger value="editor" className="gap-1"><Code className="w-3 h-3" /> YAML Editor</TabsTrigger>
              <TabsTrigger value="visual" className="gap-1"><Settings className="w-3 h-3" /> Visual Builder</TabsTrigger>
              <TabsTrigger value="preview" className="gap-1"><Eye className="w-3 h-3" /> Preview</TabsTrigger>
            </TabsList>

            {/* YAML Editor Tab */}
            <TabsContent value="editor">
              <Card className="glass-card">
                <CardContent className="p-0">
                  <textarea
                    value={yamlContent}
                    onChange={(e) => setYamlContent(e.target.value)}
                    className="w-full h-[500px] bg-black/30 text-green-400 font-mono text-sm p-4 rounded-lg border-0 focus:outline-none focus:ring-1 focus:ring-primary resize-none"
                    spellCheck={false}
                    placeholder="Paste or write your playbook YAML here..."
                  />
                </CardContent>
              </Card>
            </TabsContent>

            {/* Visual Builder Tab */}
            <TabsContent value="visual">
              <Card className="glass-card">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm">Step Builder</CardTitle>
                    <Button size="sm" variant="outline" className="text-xs h-7" onClick={() => setShowStepBuilder(!showStepBuilder)}>
                      <Plus className="w-3 h-3 mr-1" /> Add Step
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Metadata Section */}
                  <div className="grid grid-cols-3 gap-3 p-3 rounded-lg border border-border/50 bg-card/30">
                    <div><label className="text-xs text-muted-foreground">Name</label><Input className="h-8 text-sm mt-1" defaultValue="my-playbook" /></div>
                    <div><label className="text-xs text-muted-foreground">Kind</label>
                      <select className="w-full h-8 text-sm mt-1 rounded-md border border-border bg-background px-2">
                        {KINDS.map(k => <option key={k} value={k}>{k}</option>)}
                      </select>
                    </div>
                    <div><label className="text-xs text-muted-foreground">Version</label><Input className="h-8 text-sm mt-1" defaultValue="1.0.0" /></div>
                  </div>

                  {/* Compliance Frameworks */}
                  <div className="p-3 rounded-lg border border-border/50 bg-card/30">
                    <label className="text-xs text-muted-foreground mb-2 block">Compliance Frameworks</label>
                    <div className="flex flex-wrap gap-2">
                      {FRAMEWORKS.map(f => (
                        <Badge key={f} variant="outline" className="cursor-pointer hover:bg-primary/20 transition-colors text-xs">{f}</Badge>
                      ))}
                    </div>
                  </div>

                  {/* Steps */}
                  <div className="space-y-2">
                    {[
                      { name: 'check-policy', type: 'policy_check', status: 'configured' },
                      { name: 'create-ticket', type: 'adapter_call', status: 'configured' },
                    ].map((step, i) => {
                      const stepType = STEP_TYPES.find(s => s.value === step.type);
                      const Icon = stepType?.icon || FileText;
                      return (
                        <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.1 }}
                          className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:border-primary/30 transition-colors group">
                          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                            <Icon className={`w-4 h-4 ${stepType?.color || ''}`} />
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{step.name}</span>
                              <Badge variant="outline" className="text-[9px]">{step.type}</Badge>
                            </div>
                          </div>
                          <span className="text-xs text-green-400">{step.status}</span>
                          <Button variant="ghost" size="sm" className="opacity-0 group-hover:opacity-100 h-6 w-6 p-0"><Trash2 className="w-3 h-3" /></Button>
                        </motion.div>
                      );
                    })}
                  </div>

                  {/* Add Step Panel */}
                  <AnimatePresence>
                    {showStepBuilder && (
                      <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden">
                        <div className="p-3 rounded-lg border border-primary/30 bg-primary/5 space-y-3">
                          <p className="text-xs font-medium">Choose step type:</p>
                          <div className="grid grid-cols-3 gap-2">
                            {STEP_TYPES.map(st => {
                              const Icon = st.icon;
                              return (
                                <button key={st.value} className="p-2 rounded-lg border border-border/50 hover:border-primary/50 transition-colors text-left"
                                  onClick={() => { toast.success(`Added ${st.label} step`); setShowStepBuilder(false); }}>
                                  <Icon className={`w-4 h-4 ${st.color} mb-1`} />
                                  <p className="text-xs font-medium">{st.label}</p>
                                </button>
                              );
                            })}
                          </div>
                          {/* Adapter selector */}
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">Available adapters:</p>
                            <div className="flex gap-1">
                              {ADAPTERS.map(a => <Badge key={a} variant="outline" className="text-[10px] cursor-pointer hover:bg-primary/20">{a}</Badge>)}
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Preview Tab */}
            <TabsContent value="preview">
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="text-sm">Execution Preview</CardTitle>
                  <CardDescription className="text-xs">Dry-run result showing what would happen</CardDescription>
                </CardHeader>
                <CardContent>
                  {executeMutation.data ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-5 h-5 text-green-400" />
                        <span className="font-medium">{executeMutation.data.dry_run ? 'Dry Run Complete' : 'Execution Started'}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-3 text-sm">
                        <div className="p-2 rounded border border-border/50"><span className="text-muted-foreground">Execution ID:</span> <span className="font-mono">{executeMutation.data.execution_id}</span></div>
                        <div className="p-2 rounded border border-border/50"><span className="text-muted-foreground">Status:</span> <span className="text-green-400">{executeMutation.data.status}</span></div>
                        <div className="p-2 rounded border border-border/50"><span className="text-muted-foreground">Steps:</span> {executeMutation.data.steps_completed}/{executeMutation.data.steps_total}</div>
                        <div className="p-2 rounded border border-border/50"><span className="text-muted-foreground">Started:</span> {new Date(executeMutation.data.started_at).toLocaleString()}</div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p className="text-sm">Run a dry-run to see execution preview</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          {/* Validation Results */}
          {validationResult && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mt-4">
              <Card className={`glass-card ${validationResult.valid ? 'border-green-500/30' : 'border-red-500/30'}`}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    {validationResult.valid ? <CheckCircle2 className="w-5 h-5 text-green-400" /> : <AlertTriangle className="w-5 h-5 text-red-400" />}
                    <span className="font-medium text-sm">{validationResult.valid ? 'Playbook is valid' : 'Validation failed'}</span>
                  </div>
                  {validationResult.errors?.length > 0 && (
                    <div className="space-y-1">
                      {validationResult.errors.map((e: any, i: number) => (
                        <div key={i} className="text-xs text-red-400 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> <span className="font-mono">{e.field}</span>: {e.message}
                        </div>
                      ))}
                    </div>
                  )}
                  {validationResult.warnings?.length > 0 && (
                    <div className="space-y-1 mt-2">
                      {validationResult.warnings.map((w: any, i: number) => (
                        <div key={i} className="text-xs text-yellow-400 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> <span className="font-mono">{w.field}</span>: {w.message}
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}

