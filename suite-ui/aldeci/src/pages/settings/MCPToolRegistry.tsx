import { useState, useCallback } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wrench,
  FolderOpen,
  MessageSquare,
  RefreshCw,
  Wifi,
  WifiOff,
  Play,
  ChevronDown,
  ChevronUp,
  Copy,
  Eye,
  Cpu,
  Layers,
  Zap,
  Box,
  FileText,
  AlertCircle,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs';
import { ScrollArea } from '../../components/ui/scroll-area';
import { Textarea } from '../../components/ui/textarea';
import { toast } from 'sonner';
import { mcpApi } from '../../lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  category?: string;
}

interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
}

interface MCPStatus {
  status?: string;
  connected?: boolean;
  version?: string;
  server_name?: string;
  protocol_version?: string;
  tools_count?: number;
  resources_count?: number;
  prompts_count?: number;
  uptime?: string;
}

// ---------------------------------------------------------------------------
// Animation Variants
// ---------------------------------------------------------------------------

const appleEase = [0.16, 1, 0.3, 1] as const;

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      ease: appleEase,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.4,
      ease: appleEase,
    },
  },
};

const expandVariants = {
  collapsed: { height: 0, opacity: 0, overflow: 'hidden' as const },
  expanded: {
    height: 'auto',
    opacity: 1,
    overflow: 'visible' as const,
    transition: { duration: 0.3, ease: appleEase },
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractToolsArray(data: unknown): MCPTool[] {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    if (Array.isArray(obj.tools)) return obj.tools;
    if (Array.isArray(obj.items)) return obj.items;
    if (Array.isArray(obj.data)) return obj.data;
  }
  return [];
}

function extractResourcesArray(data: unknown): MCPResource[] {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    if (Array.isArray(obj.resources)) return obj.resources;
    if (Array.isArray(obj.items)) return obj.items;
    if (Array.isArray(obj.data)) return obj.data;
  }
  return [];
}

function extractPromptsArray(data: unknown): MCPPrompt[] {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    if (Array.isArray(obj.prompts)) return obj.prompts;
    if (Array.isArray(obj.items)) return obj.items;
    if (Array.isArray(obj.data)) return obj.data;
  }
  return [];
}

function isConnected(status: MCPStatus | undefined): boolean {
  if (!status) return false;
  const s = status.status?.toLowerCase();
  return s === 'connected' || s === 'healthy' || s === 'ok' || s === 'running' || status.connected === true;
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success('Copied to clipboard'),
    () => toast.error('Failed to copy'),
  );
}

// ---------------------------------------------------------------------------
// Skeleton Loaders
// ---------------------------------------------------------------------------

function OverviewSkeleton() {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {Array.from({ length: 4 }, (_, i) => (
        <Card key={i} className="border-gray-700/30 bg-gray-900/40">
          <CardContent className="p-4">
            <div className="h-3 w-16 bg-gray-700/40 rounded animate-pulse mb-3" />
            <div className="h-8 w-12 bg-gray-700/30 rounded animate-pulse" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ToolsSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {Array.from({ length: 6 }, (_, i) => (
        <Card key={i} className="border-gray-700/30 bg-gray-900/40">
          <CardContent className="p-5 space-y-3">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 bg-gray-700/40 rounded-lg animate-pulse" />
              <div className="space-y-1.5 flex-1">
                <div className="h-4 w-32 bg-gray-700/40 rounded animate-pulse" />
                <div className="h-3 w-48 bg-gray-700/30 rounded animate-pulse" />
              </div>
            </div>
            <div className="h-3 w-full bg-gray-700/20 rounded animate-pulse" />
            <div className="h-3 w-3/4 bg-gray-700/20 rounded animate-pulse" />
            <div className="flex gap-2 pt-1">
              <div className="h-7 w-16 bg-gray-700/30 rounded animate-pulse" />
              <div className="h-7 w-20 bg-gray-700/30 rounded animate-pulse" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ListSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 bg-gray-900/40 animate-pulse">
          <div className="h-8 w-8 bg-gray-700/40 rounded-lg" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-40 bg-gray-700/40 rounded" />
            <div className="h-3 w-64 bg-gray-700/30 rounded" />
          </div>
          <div className="h-6 w-20 bg-gray-700/30 rounded-full" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Empty State
// ---------------------------------------------------------------------------

function EmptyState({ icon: Icon, title, description }: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
}) {
  return (
    <motion.div
      variants={itemVariants}
      initial="hidden"
      animate="visible"
      className="flex flex-col items-center justify-center py-16 px-4"
    >
      <div className="h-16 w-16 rounded-2xl bg-gray-800/60 border border-gray-700/30 flex items-center justify-center mb-4">
        <Icon className="h-8 w-8 text-gray-500" />
      </div>
      <h3 className="text-lg font-semibold text-gray-300 mb-1">{title}</h3>
      <p className="text-sm text-gray-500 text-center max-w-md">{description}</p>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Error State
// ---------------------------------------------------------------------------

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <motion.div
      variants={itemVariants}
      initial="hidden"
      animate="visible"
      className="flex flex-col items-center justify-center py-16 px-4"
    >
      <div className="h-16 w-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-4">
        <AlertCircle className="h-8 w-8 text-red-400" />
      </div>
      <h3 className="text-lg font-semibold text-gray-300 mb-1">Failed to load data</h3>
      <p className="text-sm text-gray-500 text-center max-w-md mb-4">{message}</p>
      <Button
        variant="outline"
        size="sm"
        onClick={onRetry}
        className="gap-2 border-gray-700/50 bg-gray-900/40 text-gray-300 hover:bg-gray-800/60 hover:text-white"
      >
        <RefreshCw className="h-3.5 w-3.5" />
        Retry
      </Button>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Tool Card (with inline test panel)
// ---------------------------------------------------------------------------

function ToolCard({ tool }: { tool: MCPTool }) {
  const [expanded, setExpanded] = useState(false);
  const [testArgs, setTestArgs] = useState('{}');

  const invokeMutation = useMutation({
    mutationFn: (args: Record<string, unknown>) => mcpApi.invokeTool(tool.name, args),
    onSuccess: (data) => {
      toast.success(`Tool "${tool.name}" executed successfully`);
      setInvokeResult(JSON.stringify(data, null, 2));
    },
    onError: (err: Error) => {
      toast.error(`Tool invocation failed: ${err.message}`);
      setInvokeResult(`Error: ${err.message}`);
    },
  });

  const [invokeResult, setInvokeResult] = useState<string | null>(null);

  const handleTest = useCallback(() => {
    try {
      const parsed = JSON.parse(testArgs);
      invokeMutation.mutate(parsed);
    } catch {
      toast.error('Invalid JSON in arguments field');
    }
  }, [testArgs, invokeMutation]);

  const schemaStr = tool.inputSchema ? JSON.stringify(tool.inputSchema, null, 2) : null;
  const paramCount = tool.inputSchema && typeof tool.inputSchema === 'object'
    ? Object.keys((tool.inputSchema as Record<string, unknown>).properties ?? {}).length
    : 0;

  return (
    <motion.div variants={itemVariants}>
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/40 transition-colors">
        <CardContent className="p-5">
          {/* Header */}
          <div className="flex items-start gap-3 mb-3">
            <div className="h-9 w-9 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center flex-shrink-0">
              <Wrench className="h-4 w-4 text-indigo-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-gray-100 truncate">{tool.name}</h3>
                {tool.category && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-gray-400 border-gray-700/50">
                    {tool.category}
                  </Badge>
                )}
              </div>
              <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">
                {tool.description || 'No description available'}
              </p>
            </div>
          </div>

          {/* Metadata pills */}
          <div className="flex items-center gap-2 mb-3">
            {paramCount > 0 && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-gray-800/60 text-gray-400 border border-gray-700/30">
                {paramCount} param{paramCount !== 1 ? 's' : ''}
              </span>
            )}
            {schemaStr && (
              <button
                onClick={() => copyToClipboard(schemaStr)}
                className="text-[10px] px-2 py-0.5 rounded-full bg-gray-800/60 text-gray-400 border border-gray-700/30 hover:bg-gray-700/40 hover:text-gray-300 transition-colors flex items-center gap-1"
                aria-label={`Copy input schema for ${tool.name}`}
              >
                <Copy className="h-2.5 w-2.5" />
                Schema
              </button>
            )}
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setExpanded(!expanded)}
              className="h-7 text-xs gap-1.5 border-gray-700/50 bg-gray-800/40 text-gray-300 hover:bg-gray-700/50 hover:text-white"
              aria-label={expanded ? `Close test panel for ${tool.name}` : `Open test panel for ${tool.name}`}
            >
              <Play className="h-3 w-3" />
              Test
              {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </Button>
            {schemaStr && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyToClipboard(JSON.stringify({ tool: tool.name, schema: tool.inputSchema }, null, 2))}
                className="h-7 text-xs gap-1.5 border-gray-700/50 bg-gray-800/40 text-gray-300 hover:bg-gray-700/50 hover:text-white"
                aria-label={`Copy full definition for ${tool.name}`}
              >
                <Copy className="h-3 w-3" />
                Copy
              </Button>
            )}
          </div>

          {/* Expandable test panel */}
          <AnimatePresence>
            {expanded && (
              <motion.div
                variants={expandVariants}
                initial="collapsed"
                animate="expanded"
                exit="collapsed"
                className="mt-4 space-y-3"
              >
                <div className="border-t border-gray-700/30 pt-3">
                  <label className="text-xs font-medium text-gray-400 mb-1.5 block">
                    Arguments (JSON)
                  </label>
                  <Textarea
                    value={testArgs}
                    onChange={(e) => setTestArgs(e.target.value)}
                    placeholder='{"key": "value"}'
                    className="font-mono text-xs h-20 bg-gray-950/50 border-gray-700/40 text-gray-200 placeholder:text-gray-600 resize-none"
                    aria-label="Tool test arguments"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    onClick={handleTest}
                    disabled={invokeMutation.isPending}
                    className="h-7 text-xs gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white"
                    aria-label={`Execute ${tool.name}`}
                  >
                    {invokeMutation.isPending ? (
                      <RefreshCw className="h-3 w-3 animate-spin" />
                    ) : (
                      <Zap className="h-3 w-3" />
                    )}
                    {invokeMutation.isPending ? 'Running...' : 'Execute'}
                  </Button>
                  {invokeResult && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setInvokeResult(null)}
                      className="h-7 text-xs border-gray-700/50 bg-gray-800/40 text-gray-400 hover:text-white"
                    >
                      Clear
                    </Button>
                  )}
                </div>
                {invokeResult && (
                  <ScrollArea className="max-h-48">
                    <pre className="text-xs font-mono bg-gray-950/60 border border-gray-700/30 rounded-lg p-3 text-gray-300 whitespace-pre-wrap break-all">
                      {invokeResult}
                    </pre>
                  </ScrollArea>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Resource Row
// ---------------------------------------------------------------------------

function ResourceRow({ resource }: { resource: MCPResource }) {
  const [previewing, setPreviewing] = useState(false);
  const [content, setContent] = useState<string | null>(null);

  const previewMutation = useMutation({
    mutationFn: () => mcpApi.getResource(resource.uri),
    onSuccess: (data) => {
      setContent(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
      toast.success('Resource loaded');
    },
    onError: (err: Error) => {
      toast.error(`Failed to load resource: ${err.message}`);
      setContent(`Error: ${err.message}`);
    },
  });

  const handlePreview = useCallback(() => {
    if (previewing) {
      setPreviewing(false);
      setContent(null);
      return;
    }
    setPreviewing(true);
    previewMutation.mutate();
  }, [previewing, previewMutation]);

  return (
    <motion.div variants={itemVariants}>
      <div className="rounded-lg border border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/40 transition-colors">
        <div className="flex items-center gap-4 p-4">
          <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center flex-shrink-0">
            <FolderOpen className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-sm font-semibold text-gray-100 truncate">
              {resource.name || resource.uri}
            </h3>
            <div className="flex items-center gap-2 mt-0.5">
              <code className="text-xs text-gray-500 font-mono truncate max-w-xs">
                {resource.uri}
              </code>
              {resource.mimeType && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-gray-400 border-gray-700/50">
                  {resource.mimeType}
                </Badge>
              )}
            </div>
            {resource.description && (
              <p className="text-xs text-gray-500 mt-1 line-clamp-1">{resource.description}</p>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <Button
              variant="outline"
              size="sm"
              onClick={() => copyToClipboard(resource.uri)}
              className="h-7 text-xs gap-1 border-gray-700/50 bg-gray-800/40 text-gray-400 hover:text-white"
              aria-label={`Copy URI for ${resource.name || resource.uri}`}
            >
              <Copy className="h-3 w-3" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handlePreview}
              disabled={previewMutation.isPending}
              className="h-7 text-xs gap-1.5 border-gray-700/50 bg-gray-800/40 text-gray-300 hover:text-white"
              aria-label={previewing ? 'Close preview' : `Preview ${resource.name || resource.uri}`}
            >
              {previewMutation.isPending ? (
                <RefreshCw className="h-3 w-3 animate-spin" />
              ) : (
                <Eye className="h-3 w-3" />
              )}
              {previewing ? 'Close' : 'Preview'}
            </Button>
          </div>
        </div>
        <AnimatePresence>
          {previewing && content && (
            <motion.div
              variants={expandVariants}
              initial="collapsed"
              animate="expanded"
              exit="collapsed"
            >
              <div className="border-t border-gray-700/20 px-4 pb-4">
                <ScrollArea className="max-h-48 mt-3">
                  <pre className="text-xs font-mono bg-gray-950/60 border border-gray-700/30 rounded-lg p-3 text-gray-300 whitespace-pre-wrap break-all">
                    {content}
                  </pre>
                </ScrollArea>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Prompt Row
// ---------------------------------------------------------------------------

function PromptRow({ prompt }: { prompt: MCPPrompt }) {
  const [previewing, setPreviewing] = useState(false);
  const [previewContent, setPreviewContent] = useState<string | null>(null);

  const previewMutation = useMutation({
    mutationFn: () => mcpApi.getPrompt(prompt.name),
    onSuccess: (data) => {
      setPreviewContent(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
      toast.success('Prompt preview loaded');
    },
    onError: (err: Error) => {
      toast.error(`Failed to preview prompt: ${err.message}`);
      setPreviewContent(`Error: ${err.message}`);
    },
  });

  const handlePreview = useCallback(() => {
    if (previewing) {
      setPreviewing(false);
      setPreviewContent(null);
      return;
    }
    setPreviewing(true);
    previewMutation.mutate();
  }, [previewing, previewMutation]);

  const argCount = prompt.arguments?.length ?? 0;

  return (
    <motion.div variants={itemVariants}>
      <div className="rounded-lg border border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/40 transition-colors">
        <div className="flex items-center gap-4 p-4">
          <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center flex-shrink-0">
            <MessageSquare className="h-4 w-4 text-amber-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-gray-100 truncate">{prompt.name}</h3>
              {argCount > 0 && (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-gray-800/60 text-gray-400 border border-gray-700/30">
                  {argCount} arg{argCount !== 1 ? 's' : ''}
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 mt-0.5 line-clamp-1">
              {prompt.description || 'No description available'}
            </p>
            {prompt.arguments && prompt.arguments.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {prompt.arguments.map((arg) => (
                  <span
                    key={arg.name}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800/60 text-gray-400 font-mono border border-gray-700/30"
                  >
                    {arg.name}
                    {arg.required && <span className="text-red-400 ml-0.5">*</span>}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <Button
              variant="outline"
              size="sm"
              onClick={() => copyToClipboard(JSON.stringify(prompt, null, 2))}
              className="h-7 text-xs gap-1 border-gray-700/50 bg-gray-800/40 text-gray-400 hover:text-white"
              aria-label={`Copy definition for prompt ${prompt.name}`}
            >
              <Copy className="h-3 w-3" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handlePreview}
              disabled={previewMutation.isPending}
              className="h-7 text-xs gap-1.5 border-gray-700/50 bg-gray-800/40 text-gray-300 hover:text-white"
              aria-label={previewing ? 'Close preview' : `Preview prompt ${prompt.name}`}
            >
              {previewMutation.isPending ? (
                <RefreshCw className="h-3 w-3 animate-spin" />
              ) : (
                <Eye className="h-3 w-3" />
              )}
              {previewing ? 'Close' : 'Preview'}
            </Button>
          </div>
        </div>
        <AnimatePresence>
          {previewing && previewContent && (
            <motion.div
              variants={expandVariants}
              initial="collapsed"
              animate="expanded"
              exit="collapsed"
            >
              <div className="border-t border-gray-700/20 px-4 pb-4">
                <ScrollArea className="max-h-48 mt-3">
                  <pre className="text-xs font-mono bg-gray-950/60 border border-gray-700/30 rounded-lg p-3 text-gray-300 whitespace-pre-wrap break-all">
                    {previewContent}
                  </pre>
                </ScrollArea>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function MCPToolRegistry() {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('tools');

  // --- Data Fetching ---

  const {
    data: statusData,
    isLoading: statusLoading,
    refetch: refetchStatus,
  } = useQuery<MCPStatus>({
    queryKey: ['mcp-status'],
    queryFn: () => mcpApi.getStatus(),
    refetchInterval: 30_000,
  });

  const {
    data: toolsData,
    isLoading: toolsLoading,
    isError: toolsError,
    error: toolsErr,
    refetch: refetchTools,
  } = useQuery({
    queryKey: ['mcp-tools'],
    queryFn: () => mcpApi.getTools(),
  });

  const {
    data: resourcesData,
    isLoading: resourcesLoading,
    isError: resourcesError,
    error: resourcesErr,
    refetch: refetchResources,
  } = useQuery({
    queryKey: ['mcp-resources'],
    queryFn: () => mcpApi.getResources(),
  });

  const {
    data: promptsData,
    isLoading: promptsLoading,
    isError: promptsError,
    error: promptsErr,
    refetch: refetchPrompts,
  } = useQuery({
    queryKey: ['mcp-prompts'],
    queryFn: () => mcpApi.getPrompts(),
  });

  // --- Derived Data ---

  const connected = isConnected(statusData);
  const tools = extractToolsArray(toolsData);
  const resources = extractResourcesArray(resourcesData);
  const prompts = extractPromptsArray(promptsData);

  const filteredTools = searchQuery
    ? tools.filter(
        (t) =>
          t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          t.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          t.category?.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : tools;

  const filteredResources = searchQuery
    ? resources.filter(
        (r) =>
          r.uri.toLowerCase().includes(searchQuery.toLowerCase()) ||
          r.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          r.description?.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : resources;

  const filteredPrompts = searchQuery
    ? prompts.filter(
        (p) =>
          p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          p.description?.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : prompts;

  // --- Handlers ---

  const handleRefreshAll = useCallback(async () => {
    await Promise.all([refetchStatus(), refetchTools(), refetchResources(), refetchPrompts()]);
    toast.success('MCP registry refreshed');
  }, [refetchStatus, refetchTools, refetchResources, refetchPrompts]);

  // --- Render ---

  const isInitialLoad = statusLoading && toolsLoading;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-400 via-violet-400 to-purple-400 bg-clip-text text-transparent">
              MCP Tool Registry
            </h1>
            <Badge
              variant={connected ? 'success' : 'destructive'}
              className="text-[11px] font-medium gap-1.5"
            >
              {connected ? (
                <Wifi className="h-3 w-3" />
              ) : (
                <WifiOff className="h-3 w-3" />
              )}
              {connected ? 'Connected' : 'Disconnected'}
            </Badge>
          </div>
          <p className="mt-1 text-sm text-gray-400">
            Model Context Protocol tools, resources, and prompts for AI agent integration
            {statusData?.server_name && (
              <span className="ml-1 text-gray-500">
                &mdash; {statusData.server_name}
                {statusData.protocol_version && ` v${statusData.protocol_version}`}
              </span>
            )}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefreshAll}
          className="gap-2 border-gray-700/50 bg-gray-900/40 text-gray-300 hover:bg-gray-800/60 hover:text-white flex-shrink-0"
          aria-label="Refresh MCP registry"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Overview Stats Bar */}
      {isInitialLoad ? (
        <OverviewSkeleton />
      ) : (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="grid grid-cols-2 md:grid-cols-4 gap-4"
        >
          <motion.div variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-1.5">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Cpu className="h-3.5 w-3.5" />
                  Status
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`h-2.5 w-2.5 rounded-full ${
                      connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'
                    }`}
                  />
                  <span className="text-lg font-bold text-gray-100">
                    {connected ? 'Online' : 'Offline'}
                  </span>
                </div>
                {statusData?.uptime && (
                  <p className="text-xs text-gray-500">Uptime: {statusData.uptime}</p>
                )}
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-1.5">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Wrench className="h-3.5 w-3.5" />
                  Tools
                </div>
                <span className="text-2xl font-bold text-gray-100 tabular-nums">
                  {statusData?.tools_count ?? tools.length}
                </span>
                <p className="text-xs text-gray-500">Available for AI agents</p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-1.5">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <Layers className="h-3.5 w-3.5" />
                  Resources
                </div>
                <span className="text-2xl font-bold text-gray-100 tabular-nums">
                  {statusData?.resources_count ?? resources.length}
                </span>
                <p className="text-xs text-gray-500">Data endpoints exposed</p>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-4 flex flex-col gap-1.5">
                <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
                  <MessageSquare className="h-3.5 w-3.5" />
                  Prompts
                </div>
                <span className="text-2xl font-bold text-gray-100 tabular-nums">
                  {statusData?.prompts_count ?? prompts.length}
                </span>
                <p className="text-xs text-gray-500">Pre-built templates</p>
              </CardContent>
            </Card>
          </motion.div>
        </motion.div>
      )}

      {/* Search + Tabs */}
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search tools, resources, or prompts..."
            className="max-w-md bg-gray-900/40 border-gray-700/40 text-gray-200 placeholder:text-gray-600"
            aria-label="Search MCP registry"
          />
          {searchQuery && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSearchQuery('')}
              className="text-xs text-gray-400 hover:text-gray-200"
            >
              Clear
            </Button>
          )}
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="bg-gray-800/60 border border-gray-700/30">
            <TabsTrigger
              value="tools"
              className="data-[state=active]:bg-gray-700/60 data-[state=active]:text-gray-100 text-gray-400 gap-1.5"
            >
              <Wrench className="h-3.5 w-3.5" />
              Tools
              <span className="ml-1 text-[10px] px-1.5 py-0.5 rounded-full bg-gray-700/40 tabular-nums">
                {filteredTools.length}
              </span>
            </TabsTrigger>
            <TabsTrigger
              value="resources"
              className="data-[state=active]:bg-gray-700/60 data-[state=active]:text-gray-100 text-gray-400 gap-1.5"
            >
              <FolderOpen className="h-3.5 w-3.5" />
              Resources
              <span className="ml-1 text-[10px] px-1.5 py-0.5 rounded-full bg-gray-700/40 tabular-nums">
                {filteredResources.length}
              </span>
            </TabsTrigger>
            <TabsTrigger
              value="prompts"
              className="data-[state=active]:bg-gray-700/60 data-[state=active]:text-gray-100 text-gray-400 gap-1.5"
            >
              <MessageSquare className="h-3.5 w-3.5" />
              Prompts
              <span className="ml-1 text-[10px] px-1.5 py-0.5 rounded-full bg-gray-700/40 tabular-nums">
                {filteredPrompts.length}
              </span>
            </TabsTrigger>
          </TabsList>

          {/* Tools Tab */}
          <TabsContent value="tools" className="mt-4">
            {toolsLoading ? (
              <ToolsSkeleton />
            ) : toolsError ? (
              <ErrorState
                message={(toolsErr as Error)?.message ?? 'Failed to load MCP tools'}
                onRetry={() => refetchTools()}
              />
            ) : filteredTools.length === 0 ? (
              <EmptyState
                icon={Wrench}
                title={searchQuery ? 'No matching tools' : 'No tools registered'}
                description={
                  searchQuery
                    ? `No tools match "${searchQuery}". Try a different search term.`
                    : 'The MCP server has no tools registered yet. Tools are exposed automatically when the backend starts.'
                }
              />
            ) : (
              <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"
              >
                {filteredTools.map((tool) => (
                  <ToolCard key={tool.name} tool={tool} />
                ))}
              </motion.div>
            )}
          </TabsContent>

          {/* Resources Tab */}
          <TabsContent value="resources" className="mt-4">
            {resourcesLoading ? (
              <ListSkeleton rows={5} />
            ) : resourcesError ? (
              <ErrorState
                message={(resourcesErr as Error)?.message ?? 'Failed to load MCP resources'}
                onRetry={() => refetchResources()}
              />
            ) : filteredResources.length === 0 ? (
              <EmptyState
                icon={FolderOpen}
                title={searchQuery ? 'No matching resources' : 'No resources available'}
                description={
                  searchQuery
                    ? `No resources match "${searchQuery}". Try a different search term.`
                    : 'The MCP server has no resources registered. Resources expose data endpoints for AI agents to read.'
                }
              />
            ) : (
              <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="space-y-3"
              >
                {filteredResources.map((resource) => (
                  <ResourceRow key={resource.uri} resource={resource} />
                ))}
              </motion.div>
            )}
          </TabsContent>

          {/* Prompts Tab */}
          <TabsContent value="prompts" className="mt-4">
            {promptsLoading ? (
              <ListSkeleton rows={4} />
            ) : promptsError ? (
              <ErrorState
                message={(promptsErr as Error)?.message ?? 'Failed to load MCP prompts'}
                onRetry={() => refetchPrompts()}
              />
            ) : filteredPrompts.length === 0 ? (
              <EmptyState
                icon={MessageSquare}
                title={searchQuery ? 'No matching prompts' : 'No prompts available'}
                description={
                  searchQuery
                    ? `No prompts match "${searchQuery}". Try a different search term.`
                    : 'The MCP server has no prompt templates registered. Prompts provide pre-built interaction patterns for AI agents.'
                }
              />
            ) : (
              <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="space-y-3"
              >
                {filteredPrompts.map((prompt) => (
                  <PromptRow key={prompt.name} prompt={prompt} />
                ))}
              </motion.div>
            )}
          </TabsContent>
        </Tabs>
      </div>

      {/* Server Configuration Card */}
      <motion.div
        variants={itemVariants}
        initial="hidden"
        animate="visible"
      >
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-gray-100 text-sm">
              <Box className="h-4 w-4 text-indigo-400" />
              Server Information
            </CardTitle>
            <CardDescription className="text-gray-500">
              MCP protocol details and configuration
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-1">
                <p className="text-xs text-gray-500 uppercase tracking-wider">Server Name</p>
                <p className="text-sm font-medium text-gray-200">
                  {statusData?.server_name || 'ALdeci MCP Server'}
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-gray-500 uppercase tracking-wider">Protocol Version</p>
                <p className="text-sm font-medium text-gray-200">
                  {statusData?.protocol_version || 'MCP 1.0'}
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-gray-500 uppercase tracking-wider">Server Version</p>
                <p className="text-sm font-medium text-gray-200">
                  {statusData?.version || 'N/A'}
                </p>
              </div>
            </div>
            {statusData && (
              <details className="mt-4 group">
                <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-400 transition-colors flex items-center gap-1">
                  <FileText className="h-3 w-3" />
                  Raw server status
                </summary>
                <pre className="mt-2 text-xs font-mono bg-gray-950/50 border border-gray-700/30 rounded-lg p-3 text-gray-400 overflow-auto max-h-48">
                  {JSON.stringify(statusData, null, 2)}
                </pre>
              </details>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
