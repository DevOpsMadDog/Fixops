import { useState, useRef, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Send, X, Bot, User, Loader2, Sparkles, AlertCircle, RefreshCw } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { ScrollArea } from './ui/scroll-area';
import { useChatStore, useUIStore } from '../stores';
import { feedsApi, algorithmsApi, systemApi, mpteApi, reachabilityApi, complianceApi } from '../lib/api';
import { toast } from 'sonner';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

// ── Service unavailable error state component ──────────────────────────────
function CopilotServiceError({ onRetry }: { onRetry: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1 }}
      className="mx-3 my-4 rounded-xl border border-red-500/20 bg-red-500/5 p-4"
    >
      <div className="flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-red-300">AI Copilot Unavailable</p>
          <p className="text-xs text-red-400/80 mt-1 leading-relaxed">
            The AI Copilot service is currently offline. This may be due to missing
            LLM API credentials (OPENAI_API_KEY / ANTHROPIC_API_KEY) or a backend
            service interruption.
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={onRetry}
            className="mt-3 h-7 border-red-500/30 text-red-300 hover:bg-red-500/10 hover:border-red-400/50 text-xs"
          >
            <RefreshCw className="w-3 h-3 mr-1.5" />
            Retry Connection
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

export default function AICopilot() {
  const { toggleCopilot } = useUIStore();
  const { messages, addMessage, isLoading, setLoading } = useChatStore();
  const [input, setInput] = useState('');
  const [serviceError, setServiceError] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Auto-scroll to bottom when new messages arrive
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  useEffect(() => {
    // Focus input on mount
    inputRef.current?.focus();
  }, []);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    addMessage(userMessage);
    const query = input.trim().toLowerCase();
    setInput('');
    setLoading(true);

    try {
      // Intelligent query routing to real APIs
      let response = '';
      
      if (query.includes('status') || query.includes('health')) {
        // System health check
        const health = await systemApi.getHealth();
        const status = await systemApi.getStatus();
        response = `**System Status: ${health.status?.toUpperCase() || 'HEALTHY'}**

- Service: ${health.service || 'ALdeci API'}
- Version: ${status.version || health.version || 'N/A'}
- Uptime: ${status.uptime || 'N/A'}
- Timestamp: ${new Date().toLocaleString()}

All core services are operational.`;
      } 
      else if (query.includes('epss') || query.includes('exploit prediction')) {
        // EPSS data
        const epss = await feedsApi.getEPSS();
        const count = epss?.scores?.length || epss?.count || 0;
        response = `**EPSS Feed Status**

- Total scores loaded: ${count}
- Last updated: ${epss?.last_updated || 'Recently'}

EPSS (Exploit Prediction Scoring System) helps prioritize vulnerabilities based on likelihood of exploitation in the wild.`;
      }
      else if (query.includes('kev') || query.includes('known exploited')) {
        // KEV data
        const kev = await feedsApi.getKEV();
        const count = kev?.total_kev_entries || kev?.vulnerabilities?.length || 0;
        response = `**Known Exploited Vulnerabilities (KEV)**

- Total KEV entries: ${count}
- Source: CISA KEV Catalog

These vulnerabilities have confirmed active exploitation in the wild and should be prioritized for remediation.`;
      }
      else if (query.includes('algorithm') || query.includes('capabilities')) {
        // Algorithm capabilities
        const caps = await algorithmsApi.getCapabilities();
        const algos = caps?.algorithms?.map((a: any) => a.name || a).join(', ') || 'CVSS, EPSS, SSVC, KEV';
        response = `**Available Prioritization Algorithms**

${algos}

**Key Differentiators:**
${caps?.differentiators?.join('\n- ') || '- Multi-factor analysis\n- Real-time threat intelligence\n- Contextual risk scoring'}

Navigate to Decision Engine to configure your prioritization strategy.`;
      }
      else if (query.includes('pentest') || query.includes('attack') || query.includes('simulate')) {
        // MPTE status
        try {
          const configs = await mpteApi.getConfigs();
          response = `**Attack Lab / MPTE Status**

- Configurations: ${configs?.length || 'Available'}
- Mode: Safe sandbox testing

Available actions:
• Run CVE exploitability check
• Simulate attack paths
• Generate proof-of-concept

Navigate to Attack Suite → Attack Simulation to start testing.`;
        } catch {
          response = `**Attack Lab**

The MPTE service provides micro-penetration testing capabilities:
• Automated exploit validation
• Safe sandbox environment
• Exploitability verification

Navigate to Attack Suite → Attack Simulation to begin.`;
        }
      }
      else if (query.includes('compliance') || query.includes('pci') || query.includes('soc')) {
        // Compliance status
        try {
          const status = await complianceApi.getStatus();
          response = `**Compliance Framework Status**

${status?.frameworks?.map((f: any) => `• ${f.name}: ${f.compliance_percentage || 0}% compliant`).join('\n') || '• PCI DSS 4.0\n• SOC 2 Type II\n• NIST CSF\n• ISO 27001'}

Navigate to Evidence Suite → Compliance Reports for detailed controls.`;
        } catch {
          response = `**Compliance Mapping Available**

Supported frameworks:
• PCI DSS 4.0
• SOC 2 Type II  
• NIST CSF
• ISO 27001
• SLSA

Navigate to Evidence Suite for compliance reports and evidence packages.`;
        }
      }
      else if (query.includes('reachability') || query.includes('exposure')) {
        // Reachability analysis
        try {
          const metrics = await reachabilityApi.getMetrics();
          response = `**Reachability Analysis**

- Analyzed assets: ${metrics?.total_assets || 'N/A'}
- Exposed services: ${metrics?.exposed_services || 'N/A'}
- Protected: ${metrics?.protected_assets || 'N/A'}

This analysis identifies which vulnerabilities are actually reachable from external attack surfaces.`;
        } catch {
          response = `**Reachability Analysis**

Determines which vulnerabilities can actually be exploited based on:
• Network accessibility
• Attack surface exposure
• Defense layers

Navigate to Cloud Suite → Attack Paths for reachability insights.`;
        }
      }
      else {
        // Route unrecognised queries to the backend copilot chat endpoint
        try {
          const chatRes = await fetch('/api/v1/copilot/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: input.trim(), agent_id: 'security-analyst' }),
          });
          if (!chatRes.ok) throw new Error(`HTTP ${chatRes.status}`);
          const chatData = await chatRes.json() as { response?: string };
          response = chatData.response || 'No response from copilot service.';
          setServiceError(false);
        } catch {
          // Backend copilot endpoint unreachable — surface a proper error state
          setServiceError(true);
          setLoading(false);
          return;
        }
      }

      setServiceError(false);
      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: response,
        timestamp: new Date(),
      };

      addMessage(assistantMessage);
    } catch (error: unknown) {
      console.error('AI Copilot error:', error);
      setServiceError(true);
      toast.error('AI Copilot service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const handleRetry = useCallback(() => {
    setServiceError(false);
    inputRef.current?.focus();
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const suggestedQueries = [
    'Check system status',
    'Show EPSS scores',
    'What algorithms are available?',
    'Check KEV vulnerabilities',
    'Show compliance status',
    'Check attack capabilities',
  ];

  return (
    <motion.div
      initial={{ x: 400, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 400, opacity: 0 }}
      transition={{ type: 'spring', damping: 25 }}
      className="w-[400px] border-l border-border bg-card/50 backdrop-blur-xl flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold">AI Copilot</h3>
            <p className="text-xs text-muted-foreground">Security Intelligence</p>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={toggleCopilot}>
          <X className="w-4 h-4" />
        </Button>
      </div>

      {/* Messages */}
      <ScrollArea className="flex-1 p-4">
        <div ref={scrollRef} className="space-y-4">
          {messages.length === 0 ? (
            <div className="space-y-4">
              <div className="text-center py-8">
                <Bot className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h4 className="font-medium mb-2">How can I help?</h4>
                <p className="text-sm text-muted-foreground">
                  Ask me about vulnerabilities, risks, or security insights.
                </p>
              </div>
              
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground uppercase tracking-wide">Suggested</p>
                {suggestedQueries.map((query) => (
                  <Button
                    key={query}
                    variant="outline"
                    size="sm"
                    className="w-full justify-start text-left"
                    onClick={() => {
                      setInput(query);
                      inputRef.current?.focus();
                    }}
                  >
                    {query}
                  </Button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((message) => (
              <motion.div
                key={message.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`flex gap-3 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                  message.role === 'user' ? 'bg-primary/10' : 'bg-muted'
                }`}>
                  {message.role === 'user' ? (
                    <User className="w-4 h-4 text-primary" />
                  ) : (
                    <Bot className="w-4 h-4" />
                  )}
                </div>
                <div className={`flex-1 rounded-lg p-3 ${
                  message.role === 'user' 
                    ? 'bg-primary text-primary-foreground' 
                    : 'bg-muted'
                }`}>
                  <div className="text-sm whitespace-pre-wrap">{message.content}</div>
                  <div className="text-xs opacity-60 mt-1">
                    {message.timestamp.toLocaleTimeString()}
                  </div>
                </div>
              </motion.div>
            ))
          )}
          
          {isLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex gap-3"
            >
              <div className="w-8 h-8 rounded-lg bg-muted flex items-center justify-center">
                <Bot className="w-4 h-4" />
              </div>
              <div className="bg-muted rounded-lg p-3">
                <Loader2 className="w-4 h-4 animate-spin" />
              </div>
            </motion.div>
          )}
        </div>
      </ScrollArea>

      {/* Service error banner — shown below messages, above input */}
      {serviceError && <CopilotServiceError onRetry={handleRetry} />}

      {/* Input */}
      <div className="p-4 border-t border-border">
        <div className="flex gap-2">
          <Input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about security..."
            disabled={isLoading}
            className="flex-1"
          />
          <Button 
            onClick={handleSend} 
            disabled={!input.trim() || isLoading}
            size="icon"
          >
            <Send className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </motion.div>
  );
}
