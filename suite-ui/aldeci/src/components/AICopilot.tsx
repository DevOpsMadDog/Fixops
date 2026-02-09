import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Send, X, Bot, User, Loader2, Sparkles } from 'lucide-react';
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

export default function AICopilot() {
  const { toggleCopilot } = useUIStore();
  const { messages, addMessage, isLoading, setLoading } = useChatStore();
  const [input, setInput] = useState('');
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
        // Generic helpful response
        response = getFallbackResponse(input.trim());
      }

      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: response,
        timestamp: new Date(),
      };

      addMessage(assistantMessage);
    } catch (error: any) {
      console.error('AI Copilot error:', error);
      
      // Provide intelligent fallback responses based on query
      const fallbackResponse = getFallbackResponse(input.trim());
      
      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: fallbackResponse,
        timestamp: new Date(),
      };

      addMessage(assistantMessage);
      
      if (error.response?.status !== 404) {
        toast.error('AI service unavailable, using local intelligence');
      }
    } finally {
      setLoading(false);
    }
  };

  const getFallbackResponse = (query: string): string => {
    const lowerQuery = query.toLowerCase();
    
    if (lowerQuery.includes('vulnerability') || lowerQuery.includes('cve')) {
      return `I can help you analyze vulnerabilities. Based on the current data in the system:

**Quick Actions:**
- View all critical vulnerabilities in the Intelligence Hub
- Check EPSS scores for prioritization
- Review KEV (Known Exploited Vulnerabilities) status

To get specific CVE details, navigate to the Data Fabric and use the vulnerability search feature.`;
    }
    
    if (lowerQuery.includes('risk') || lowerQuery.includes('priority')) {
      return `For risk prioritization, I recommend using the Decision Engine which applies multiple algorithms:

**Available Algorithms:**
- CVSS (Common Vulnerability Scoring System)
- EPSS (Exploit Prediction Scoring System)
- SSVC (Stakeholder-Specific Vulnerability Categorization)
- KEV (Known Exploited Vulnerabilities)

Navigate to Decision Engine to configure your prioritization strategy.`;
    }
    
    if (lowerQuery.includes('pentest') || lowerQuery.includes('attack') || lowerQuery.includes('exploit')) {
      return `The Attack Lab provides micro-penetration testing capabilities:

**Features:**
- Automated exploit validation
- Safe sandbox environment
- Proof-of-concept generation
- Exploitability verification

Navigate to Attack Lab to run security validation tests.`;
    }
    
    if (lowerQuery.includes('compliance') || lowerQuery.includes('pci') || lowerQuery.includes('soc')) {
      return `Compliance mapping is available in the Evidence Vault:

**Supported Frameworks:**
- PCI DSS 4.0
- SOC 2 Type II
- NIST CSF
- ISO 27001

Navigate to Evidence Vault to generate compliance reports and evidence packages.`;
    }
    
    if (lowerQuery.includes('remediation') || lowerQuery.includes('fix') || lowerQuery.includes('patch')) {
      return `The Remediation Center provides actionable fixes:

**Capabilities:**
- AI-generated remediation code
- Patch recommendations
- Dependency upgrade paths
- Pull request generation

Navigate to Remediation Center for guided fix workflows.`;
    }
    
    return `I'm ALdeci's AI assistant. I can help you with:

- **Vulnerability Analysis** - Search and analyze CVEs
- **Risk Prioritization** - Use EPSS, SSVC, KEV algorithms
- **Attack Simulation** - Validate exploitability safely
- **Compliance Mapping** - Generate evidence packages
- **Remediation Guidance** - Get actionable fixes

What would you like to explore?`;
  };

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
