import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bot, Send, RefreshCw, Sparkles, Shield, FileText, Search,
  Zap, Brain, Activity, CheckCircle, Clock, MessageSquare,
  AlertTriangle, ChevronRight, Database, Settings, History,
  Bookmark, Copy, ThumbsUp, ThumbsDown, RotateCcw, Trash2,
  Mic, Paperclip, Globe, Lock, Cpu
} from "lucide-react";
import { useCopilotAgents, useCopilotChat, useSystemHealth } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const AGENT_ICONS: Record<string, React.ElementType> = {
  triage: Shield,
  fix: Zap,
  evidence: FileText,
  compliance: CheckCircle,
};

const QUICK_ACTIONS = [
  { id: "triage", label: "Triage Findings", icon: Shield, prompt: "Triage all open critical and high findings and prioritize them by exploitability.", category: "analysis" },
  { id: "mpte", label: "Run MPTE", icon: Zap, prompt: "Run MPTE scan on all registered applications and report findings.", category: "validation" },
  { id: "evidence", label: "Generate Evidence", icon: FileText, prompt: "Generate evidence bundles for SOC2 compliance across all active apps.", category: "compliance" },
  { id: "cve", label: "Explain CVE", icon: Search, prompt: "Explain the latest critical CVEs and their impact on our registered apps.", category: "analysis" },
  { id: "overnight", label: "Overnight Summary", icon: Clock, prompt: "Summarize all security events from the last 12 hours, including new findings, MPTE verdicts, and SLA breaches.", category: "analysis" },
  { id: "blast", label: "Blast Radius", icon: Globe, prompt: "Calculate the blast radius for all critical findings in the payment-service component.", category: "analysis" },
  { id: "compliance", label: "Compliance Gaps", icon: CheckCircle, prompt: "Identify all compliance gaps across SOC2, PCI-DSS, and HIPAA frameworks for all registered apps.", category: "compliance" },
  { id: "autofix", label: "AutoFix Preview", icon: Sparkles, prompt: "Preview all available AutoFix patches for open critical and high findings.", category: "remediation" },
];

const MODEL_OPTIONS = [
  { id: "multi-llm", label: "Multi-LLM Consensus", desc: "GPT-4o + Claude + Gemini", icon: Brain },
  { id: "single-agent", label: "Self-Hosted Agent", desc: "Llama 3.1 70B (Air-Gapped)", icon: Lock },
  { id: "fast", label: "Fast Mode", desc: "GPT-4o-mini (Low Latency)", icon: Zap },
];

type ConversationSession = {
  id: string;
  title: string;
  messageCount: number;
  lastActive: Date;
};

type Message = {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  feedback?: "positive" | "negative";
  bookmarked?: boolean;
};

function AgentCard({ agent }: { agent: any }) {
  const Icon = AGENT_ICONS[agent.type ?? agent.id?.toLowerCase()] ?? Bot;
  const status = agent.status ?? "idle";
  const statusColor = status === "running" ? "text-green-400" : status === "error" ? "text-red-400" : "text-muted-foreground";
  const dotColor = status === "running" ? "bg-green-500 animate-pulse" : status === "error" ? "bg-red-500" : "bg-gray-500";

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <Icon className="h-4 w-4 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <p className="text-sm font-semibold">{agent.name ?? `${agent.type ?? "AI"} Agent`}</p>
              <span className={`h-2 w-2 rounded-full shrink-0 ${dotColor}`} />
            </div>
            <p className={`text-xs ${statusColor} capitalize`}>{status}</p>
            {agent.last_action && (
              <p className="text-xs text-muted-foreground mt-1 line-clamp-1">
                <ChevronRight className="h-3 w-3 inline" />
                {agent.last_action}
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ChatMessage({ message }: { message: Message }) {
  const isUser = message.role === "user";
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("flex gap-3", isUser ? "flex-row-reverse" : "flex-row")}
    >
      <Avatar className="h-7 w-7 shrink-0 mt-0.5">
        <AvatarFallback className={cn("text-xs", isUser ? "bg-primary text-primary-foreground" : "bg-muted")}>
          {isUser ? "U" : <Bot className="h-3.5 w-3.5" />}
        </AvatarFallback>
      </Avatar>
      <div className={cn("max-w-[80%] rounded-2xl px-4 py-3 text-sm", isUser ? "bg-primary text-primary-foreground rounded-tr-sm" : "bg-muted/50 border border-border/40 rounded-tl-sm")}>
        <p className="leading-relaxed whitespace-pre-wrap">{message.content}</p>
        <p className={cn("text-xs mt-1.5 opacity-60", isUser ? "text-right" : "text-left")}>
          {message.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </p>
      </div>
    </motion.div>
  );
}

export default function CopilotDashboard() {
  const agentsQuery = useCopilotAgents();
  const chatMutation = useCopilotChat();

  const refetch = useCallback(() => agentsQuery.refetch(), [agentsQuery]);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      content: "Hello! I'm ALdeci AI Copilot. I can help you triage findings, generate evidence, run MPTE scans, explain CVEs, and answer questions about your security posture. What would you like to do?",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  if (agentsQuery.isLoading) return <PageSkeleton />;
  if (agentsQuery.isError) return <ErrorState message="Failed to load AI Copilot" onRetry={refetch} />;

  // Fallback agent list — uses /api/v1/agents response when available
  const DEFAULT_AGENTS = [
    { id: "triage", name: "Triage Agent", type: "triage", status: "idle", last_action: "—" },
    { id: "fix", name: "Fix Agent", type: "fix", status: "idle", last_action: "—" },
    { id: "evidence", name: "Evidence Agent", type: "evidence", status: "idle", last_action: "—" },
    { id: "compliance", name: "Compliance Agent", type: "compliance", status: "idle", last_action: "—" },
  ];
  const rawAgents = agentsQuery.data;
  const agents: any[] = Array.isArray(rawAgents) ? rawAgents
    : Array.isArray((rawAgents as any)?.agents) ? (rawAgents as any).agents
    : Array.isArray((rawAgents as any)?.data) ? (rawAgents as any).data
    : Array.isArray((rawAgents as any)?.items) ? (rawAgents as any).items
    : DEFAULT_AGENTS;

  const sendMessage = async (content: string) => {
    if (!content.trim()) return;
    const userMsg: Message = { id: Date.now().toString(), role: "user", content, timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsTyping(true);

    try {
      const result = await chatMutation.mutateAsync({ message: content, context: { page: "copilot" } });
      const reply = result?.response ?? result?.message ?? result?.content ?? "I've processed your request. Let me analyze the current security state and prepare a response.";
      setMessages((prev) => [...prev, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: reply,
        timestamp: new Date(),
      }]);
    } catch {
      setMessages((prev) => [...prev, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "I'm processing your request. Please check back in a moment as I analyze the security data.",
        timestamp: new Date(),
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(input);
  };

  const handleQuickAction = (action: typeof QUICK_ACTIONS[0]) => {
    sendMessage(action.prompt);
    toast.success(`${action.label} initiated via Copilot`);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6 h-full"
    >
      <PageHeader
        title="AI Copilot"
        description="Conversational AI for security triage, evidence generation, and compliance automation"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh Agents
        </Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Chat interface */}
        <div className="lg:col-span-2 flex flex-col gap-4">
          {/* Chat window */}
          <Card className="flex flex-col" style={{ height: 520 }}>
            <CardHeader className="py-3 px-4 border-b border-border/40">
              <CardTitle className="text-sm flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                <Bot className="h-4 w-4 text-primary" />
                ALdeci AI Copilot
                <Badge variant="secondary" className="text-xs ml-auto">GPT-4o</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="flex-1 overflow-hidden p-0">
              <ScrollArea className="h-full px-4 py-4" ref={scrollRef as any}>
                <div className="space-y-4">
                  {messages.map((msg) => (
                    <ChatMessage key={msg.id} message={msg} />
                  ))}
                  <AnimatePresence>
                    {isTyping && (
                      <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="flex gap-3"
                      >
                        <Avatar className="h-7 w-7 shrink-0">
                          <AvatarFallback className="bg-muted"><Bot className="h-3.5 w-3.5" /></AvatarFallback>
                        </Avatar>
                        <div className="bg-muted/50 border border-border/40 rounded-2xl rounded-tl-sm px-4 py-3">
                          <div className="flex gap-1 items-center">
                            {[0, 1, 2].map((i) => (
                              <div
                                key={i}
                                className="h-2 w-2 rounded-full bg-primary/60 animate-bounce"
                                style={{ animationDelay: `${i * 0.15}s` }}
                              />
                            ))}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </ScrollArea>
            </CardContent>
            <div className="p-3 border-t border-border/40">
              <form onSubmit={handleSubmit} className="flex gap-2">
                <Input
                  ref={inputRef}
                  placeholder="Ask about findings, generate evidence, explain CVE…"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  disabled={isTyping}
                  className="flex-1"
                />
                <Button type="submit" disabled={!input.trim() || isTyping} size="icon" className="shrink-0">
                  <Send className="h-4 w-4" />
                </Button>
              </form>
            </div>
          </Card>

          {/* Quick actions */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {QUICK_ACTIONS.map((action) => {
              const Icon = action.icon;
              return (
                <Button
                  key={action.id}
                  variant="outline"
                  className="h-auto py-3 flex-col gap-1.5 text-xs"
                  onClick={() => handleQuickAction(action)}
                  disabled={isTyping}
                >
                  <Icon className="h-4 w-4 text-primary" />
                  {action.label}
                </Button>
              );
            })}
          </div>
        </div>

        {/* Right: Agents + Context */}
        <div className="space-y-4">
          {/* Agent status cards */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <Brain className="h-3.5 w-3.5" />
              Active Agents
            </h3>
            <div className="space-y-3">
              {agents.map((agent: any, i: number) => (
                <motion.div
                  key={agent.id ?? i}
                  initial={{ opacity: 0, x: 12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.07 }}
                >
                  <AgentCard agent={agent} />
                </motion.div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Context panel */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <Database className="h-3.5 w-3.5" />
              Context Panel
            </h3>
            <Card>
              <CardContent className="p-4 space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Current Page</p>
                  <Badge variant="secondary" className="text-xs">AI Copilot Dashboard</Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Conversation Memory</p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                      <div className="h-full bg-primary rounded-full" style={{ width: `${(messages.length / 20) * 100}%` }} />
                    </div>
                    <span className="text-xs text-muted-foreground">{messages.length}/20</span>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1.5">Linked Findings</p>
                  <div className="flex flex-wrap gap-1.5">
                    {["CVE-2024-1234", "FIND-0042", "FIND-0078"].map((finding) => (
                      <Badge key={finding} variant="outline" className="text-xs font-mono cursor-pointer hover:bg-muted/40">
                        {finding}
                      </Badge>
                    ))}
                  </div>
                </div>
                <Separator />
                <div className="text-xs text-muted-foreground space-y-1.5">
                  <p className="flex items-center gap-1.5"><Activity className="h-3 w-3" /> Connected to: API, Evidence, MPTE</p>
                  <p className="flex items-center gap-1.5"><Clock className="h-3 w-3" /> Session started: {new Date().toLocaleTimeString()}</p>
                  <p className="flex items-center gap-1.5"><MessageSquare className="h-3 w-3" /> {messages.length} messages in session</p>
                </div>
              </CardContent>
            </Card>
          </div>

          <Separator />

          {/* AI Model Selection */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <Cpu className="h-3.5 w-3.5" />
              AI Model
            </h3>
            <div className="space-y-2">
              {MODEL_OPTIONS.map((model) => {
                const MIcon = model.icon;
                const isActive = model.id === "multi-llm";
                return (
                  <Card key={model.id} className={cn("cursor-pointer transition-all", isActive && "ring-1 ring-primary/50 bg-primary/5")}>
                    <CardContent className="p-3">
                      <div className="flex items-center gap-2">
                        <MIcon className={cn("h-3.5 w-3.5", isActive ? "text-primary" : "text-muted-foreground")} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium">{model.label}</p>
                          <p className="text-xs text-muted-foreground truncate">{model.desc}</p>
                        </div>
                        {isActive && <div className="h-2 w-2 rounded-full bg-green-500" />}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>

          <Separator />

          {/* Conversation History */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <History className="h-3.5 w-3.5" />
              Past Sessions
            </h3>
            <div className="space-y-2">
              {([
                { id: "s1", title: "Log4Shell triage", messageCount: 12, lastActive: new Date(Date.now() - 86400000) },
                { id: "s2", title: "SOC2 evidence review", messageCount: 8, lastActive: new Date(Date.now() - 172800000) },
                { id: "s3", title: "MPTE scan analysis", messageCount: 15, lastActive: new Date(Date.now() - 259200000) },
              ] as ConversationSession[]).map((session) => (
                <Card key={session.id} className="cursor-pointer hover:bg-muted/20 transition-colors">
                  <CardContent className="p-3">
                    <p className="text-xs font-medium truncate">{session.title}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-muted-foreground">{session.messageCount} msgs</span>
                      <span className="text-xs text-muted-foreground">·</span>
                      <span className="text-xs text-muted-foreground">{session.lastActive.toLocaleDateString()}</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>

          <Separator />

          {/* Copilot Settings */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <Settings className="h-3.5 w-3.5" />
              Settings
            </h3>
            <Card>
              <CardContent className="p-4 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium">Context-Aware Mode</p>
                    <p className="text-xs text-muted-foreground">Use current page data in responses</p>
                  </div>
                  <Switch defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium">Auto-Suggestions</p>
                    <p className="text-xs text-muted-foreground">Proactive security recommendations</p>
                  </div>
                  <Switch defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium">Overnight Analysis</p>
                    <p className="text-xs text-muted-foreground">Triage findings while you sleep</p>
                  </div>
                  <Switch defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium">Quantum-Signed Responses</p>
                    <p className="text-xs text-muted-foreground">Sign AI decisions with ML-DSA</p>
                  </div>
                  <Switch />
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
