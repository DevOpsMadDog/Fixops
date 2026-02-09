import { useState, useRef, useEffect } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send,
  Bot,
  User,
  Loader2,
  Sparkles,
  Shield,
  Zap,
  Target,
  FileCode,
  Network,
  Copy,
  XCircle,
} from 'lucide-react';
import { Card, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { mpteApi, microPentestApi, reachabilityApi } from '../../lib/api';
import { toast } from 'sonner';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  metadata?: {
    type?: 'attack' | 'scan' | 'analysis' | 'exploit' | 'info';
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    tool?: string;
    findings?: any[];
    cve?: string;
    target?: string;
  };
}

interface AttackTarget {
  type: 'cve' | 'host' | 'network' | 'application';
  value: string;
  description?: string;
}

export default function MPTEChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'system',
      content: `🛡️ **MPTE Attack Lab Ready**

I'm your AI-powered security testing assistant. I can help you with:

• **CVE Analysis** - Analyze vulnerabilities and exploitation paths
• **Reachability Testing** - Check if vulnerabilities are exploitable in your environment
• **Attack Simulation** - Safe, controlled attack path modeling
• **Security Scanning** - Automated vulnerability scanning
• **Exploit Research** - MITRE ATT&CK mapping and research

**Quick Commands:**
- \`analyze CVE-2024-XXXX\` - Deep-dive into a specific CVE
- \`scan target [host/url]\` - Run security scan
- \`attack-path [cve]\` - Model attack paths
- \`reachability [cve]\` - Check exploitability

Type your request or select a quick action below.`,
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [currentTarget, setCurrentTarget] = useState<AttackTarget | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Query MPTE status
  const { data: pentestStatus } = useQuery({
    queryKey: ['pentest-health'],
    queryFn: () => microPentestApi.getHealth(),
    retry: false,
  });

  // Query available capabilities
  const { data: toolsData } = useQuery({
    queryKey: ['pentest-capabilities'],
    queryFn: () => mpteApi.getConfigs(),
    retry: false,
  });

  // Chat mutation
  const chatMutation = useMutation({
    mutationFn: async (message: string) => {
      // Parse command type
      const lowerMessage = message.toLowerCase();
      
      if (lowerMessage.startsWith('analyze cve-') || lowerMessage.includes('cve-')) {
        const cveMatch = message.match(/CVE-\d{4}-\d+/i);
        if (cveMatch) {
          // Use getExploitability for CVE analysis
          return await mpteApi.getExploitability(cveMatch[0]);
        }
      }
      
      if (lowerMessage.startsWith('scan ') || lowerMessage.includes('scan target')) {
        const target = message.replace(/scan (target )?/i, '').trim();
        // Use comprehensiveScan for scanning
        return await mpteApi.comprehensiveScan({ 
          target,
          scope: 'full'
        });
      }
      
      if (lowerMessage.startsWith('attack-path') || lowerMessage.includes('attack path')) {
        // Use reachability getMetrics for attack paths
        return await reachabilityApi.getMetrics();
      }
      
      if (lowerMessage.startsWith('reachability') || lowerMessage.includes('reachable')) {
        // Use reachability metrics
        return await reachabilityApi.getMetrics();
      }

      // Default: Use the general pentest run for other requests
      return await microPentestApi.run({
        cve_ids: [],
        target_urls: [message],
        context: { safe_mode: true }
      });
    },
    onSuccess: (data) => {
      const response = formatResponse(data);
      addMessage({
        role: 'assistant',
        content: response.content,
        metadata: response.metadata,
      });
    },
    onError: (error: any) => {
      addMessage({
        role: 'assistant',
        content: `⚠️ **Error Processing Request**\n\n${error.message || 'Failed to process your request. Please try again.'}\n\nMake sure the backend is running and the MPTE service is available.`,
        metadata: { type: 'info', severity: 'high' },
      });
    },
  });

  // Format API response for chat display
  const formatResponse = (data: any): { content: string; metadata?: ChatMessage['metadata'] } => {
    if (!data) {
      return { content: 'No response received from the server.' };
    }

    // CVE Analysis response
    if (data.cve_id || data.cve) {
      const cve = data.cve_id || data.cve;
      return {
        content: `## 🔍 CVE Analysis: ${cve}

**Severity:** ${data.severity || 'Unknown'} | **CVSS:** ${data.cvss_score || 'N/A'}

**Description:**
${data.description || 'No description available'}

**Affected Products:**
${data.affected_products?.join(', ') || 'Not specified'}

**EPSS Score:** ${data.epss_score ? `${(data.epss_score * 100).toFixed(2)}%` : 'N/A'}
**KEV Status:** ${data.in_kev ? '⚠️ In CISA KEV' : '✅ Not in KEV'}

**Exploitation:**
- Public Exploit: ${data.has_public_exploit ? '⚠️ Yes' : '✅ No'}
- In-the-wild: ${data.exploited_in_wild ? '🔴 Yes' : '✅ No'}

**Recommendations:**
${data.recommendations?.map((r: string) => `• ${r}`).join('\n') || '• Patch as soon as possible\n• Monitor for exploitation attempts'}`,
        metadata: {
          type: 'analysis',
          severity: data.severity?.toLowerCase() as any,
          cve: cve,
        },
      };
    }

    // Attack path response
    if (data.attack_paths || data.paths) {
      const paths = data.attack_paths || data.paths || [];
      return {
        content: `## 🎯 Attack Path Analysis

**Total Paths Found:** ${paths.length}

${paths.slice(0, 5).map((path: any, i: number) => `
### Path ${i + 1}: ${path.name || 'Unnamed'}
- **Risk Score:** ${path.risk_score || 'N/A'}
- **Steps:** ${path.steps?.length || 0}
- **Techniques:** ${path.techniques?.join(', ') || 'N/A'}
`).join('\n')}

${paths.length > 5 ? `\n*... and ${paths.length - 5} more paths*` : ''}`,
        metadata: { type: 'attack' },
      };
    }

    // Scan response
    if (data.vulnerabilities || data.findings) {
      const findings = data.vulnerabilities || data.findings || [];
      return {
        content: `## 🔎 Scan Results

**Target:** ${data.target || 'Unknown'}
**Status:** ${data.status || 'Completed'}
**Findings:** ${findings.length}

${findings.slice(0, 10).map((f: any) => `
- **${f.severity?.toUpperCase() || 'INFO'}** | ${f.title || f.name || 'Finding'}
  ${f.description?.slice(0, 100) || ''}...
`).join('\n')}

${findings.length > 10 ? `\n*... and ${findings.length - 10} more findings*` : ''}`,
        metadata: { type: 'scan', findings },
      };
    }

    // Reachability response
    if (data.reachable !== undefined || data.reachability) {
      return {
        content: `## 🌐 Reachability Analysis

**Status:** ${data.reachable ? '⚠️ REACHABLE' : '✅ NOT REACHABLE'}

**Analysis:**
${data.analysis || data.explanation || 'No detailed analysis available'}

**Network Path:**
${data.network_path?.join(' → ') || 'N/A'}

**Blocking Controls:**
${data.blocking_controls?.map((c: string) => `• ${c}`).join('\n') || '• None identified'}`,
        metadata: {
          type: 'analysis',
          severity: data.reachable ? 'high' : 'low',
        },
      };
    }

    // Generic chat response
    if (data.response || data.message || data.content) {
      return {
        content: data.response || data.message || data.content,
        metadata: { type: 'info' },
      };
    }

    // Fallback
    return {
      content: `\`\`\`json
${JSON.stringify(data, null, 2)}
\`\`\``,
      metadata: { type: 'info' },
    };
  };

  const addMessage = (message: Omit<ChatMessage, 'id' | 'timestamp'>) => {
    const newMessage: ChatMessage = {
      ...message,
      id: Date.now().toString(),
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, newMessage]);
  };

  const handleSend = async () => {
    if (!input.trim() || chatMutation.isPending) return;

    const userMessage = input.trim();
    setInput('');
    
    addMessage({
      role: 'user',
      content: userMessage,
    });

    await chatMutation.mutateAsync(userMessage);
  };

  const handleQuickAction = async (action: string) => {
    setInput(action);
    inputRef.current?.focus();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Severity badge color
  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-12rem)]">
      {/* Header with status */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
            <Zap className="w-5 h-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold">MPTE Attack Lab</h2>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className={`w-2 h-2 rounded-full ${(pentestStatus as any)?.status === 'ready' ? 'bg-green-500' : 'bg-yellow-500'}`} />
              {(pentestStatus as any)?.status || 'Connecting...'}
              {(toolsData as any)?.capabilities && (
                <span>• {((toolsData as any)?.capabilities as string[])?.length || 0} capabilities</span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {currentTarget && (
            <Badge variant="outline" className="gap-1">
              <Target className="w-3 h-3" />
              {currentTarget.value}
              <button onClick={() => setCurrentTarget(null)} className="ml-1 hover:text-red-400">
                <XCircle className="w-3 h-3" />
              </button>
            </Badge>
          )}
        </div>
      </div>

      {/* Chat messages */}
      <Card className="flex-1 glass-card overflow-hidden">
        <CardContent className="p-4 h-full flex flex-col">
          <div className="flex-1 overflow-y-auto space-y-4 pr-2">
            <AnimatePresence>
              {messages.map((message) => (
                <motion.div
                  key={message.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className={`flex gap-3 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  {/* Avatar */}
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                    message.role === 'user' 
                      ? 'bg-primary/20' 
                      : message.role === 'system'
                      ? 'bg-purple-500/20'
                      : 'bg-gradient-to-br from-red-500/20 to-orange-500/20'
                  }`}>
                    {message.role === 'user' ? (
                      <User className="w-4 h-4" />
                    ) : message.role === 'system' ? (
                      <Sparkles className="w-4 h-4 text-purple-400" />
                    ) : (
                      <Bot className="w-4 h-4 text-orange-400" />
                    )}
                  </div>

                  {/* Message content */}
                  <div className={`flex-1 ${message.role === 'user' ? 'text-right' : ''}`}>
                    <div
                      className={`inline-block max-w-[85%] p-3 rounded-lg ${
                        message.role === 'user'
                          ? 'bg-primary text-primary-foreground'
                          : 'bg-muted/50 border border-border'
                      }`}
                    >
                      {message.metadata?.severity && (
                        <Badge className={`mb-2 ${getSeverityColor(message.metadata.severity)}`}>
                          {message.metadata.severity.toUpperCase()}
                        </Badge>
                      )}
                      <div className="text-sm whitespace-pre-wrap prose prose-invert prose-sm max-w-none">
                        {message.content}
                      </div>
                      {message.role === 'assistant' && (
                        <div className="mt-2 pt-2 border-t border-border/50 flex items-center gap-2 text-xs text-muted-foreground">
                          <button
                            onClick={() => copyToClipboard(message.content)}
                            className="hover:text-foreground flex items-center gap-1"
                          >
                            <Copy className="w-3 h-3" /> Copy
                          </button>
                          <span>•</span>
                          <span>{message.timestamp.toLocaleTimeString()}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>

            {/* Typing indicator */}
            {chatMutation.isPending && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex gap-3"
              >
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500/20 to-orange-500/20 flex items-center justify-center">
                  <Loader2 className="w-4 h-4 text-orange-400 animate-spin" />
                </div>
                <div className="bg-muted/50 border border-border rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <span>Analyzing</span>
                    <span className="flex gap-1">
                      <span className="w-1 h-1 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                      <span className="w-1 h-1 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                      <span className="w-1 h-1 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                    </span>
                  </div>
                </div>
              </motion.div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick actions */}
          <div className="pt-3 border-t border-border mt-3">
            <div className="flex flex-wrap gap-2 mb-3">
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={() => handleQuickAction('analyze CVE-2024-3400')}
              >
                <FileCode className="w-3 h-3 mr-1" />
                Analyze CVE
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={() => handleQuickAction('scan target localhost')}
              >
                <Network className="w-3 h-3 mr-1" />
                Quick Scan
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={() => handleQuickAction('attack-path analysis')}
              >
                <Target className="w-3 h-3 mr-1" />
                Attack Paths
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={() => handleQuickAction('show reachability report')}
              >
                <Shield className="w-3 h-3 mr-1" />
                Reachability
              </Button>
            </div>

            {/* Input */}
            <div className="flex gap-2">
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                placeholder="Type a command or ask a question..."
                className="flex-1 bg-muted/50 border border-border rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                disabled={chatMutation.isPending}
              />
              <Button
                onClick={handleSend}
                disabled={!input.trim() || chatMutation.isPending}
                className="shrink-0"
              >
                {chatMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
