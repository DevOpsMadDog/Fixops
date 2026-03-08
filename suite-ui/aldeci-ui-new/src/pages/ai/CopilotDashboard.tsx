import { useState, useRef, useEffect } from "react";
import {
  Bot,
  Send,
  ShieldAlert,
  FileText,
  SearchCode,
  Wrench,
  ChevronDown,
  User,
  Loader2,
  Cpu,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type ModelId = "gpt-4o" | "claude-3-5" | "gemini";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface QuickAction {
  id: string;
  icon: React.ReactNode;
  title: string;
  description: string;
  prompt: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const MODELS: { id: ModelId; label: string; provider: string }[] = [
  { id: "gpt-4o", label: "GPT-4o", provider: "OpenAI" },
  { id: "claude-3-5", label: "Claude 3.5", provider: "Anthropic" },
  { id: "gemini", label: "Gemini", provider: "Google" },
];

const QUICK_ACTIONS: QuickAction[] = [
  {
    id: "analyze-threat",
    icon: <ShieldAlert className="h-5 w-5 text-destructive" />,
    title: "Analyze Threat",
    description: "Deep-dive analysis of the highest-severity active finding.",
    prompt: "Analyze the most critical active threat in the current workspace and provide a detailed risk assessment.",
  },
  {
    id: "generate-report",
    icon: <FileText className="h-5 w-5 text-primary" />,
    title: "Generate Report",
    description: "Produce an executive-ready security posture summary.",
    prompt: "Generate an executive security posture report summarizing open findings, risk trends, and remediation progress.",
  },
  {
    id: "review-findings",
    icon: <SearchCode className="h-5 w-5 text-warning" />,
    title: "Review Findings",
    description: "Triage and prioritize all open findings by exploitability.",
    prompt: "Review all open findings and prioritize them by real-world exploitability, providing a ranked action list.",
  },
  {
    id: "suggest-remediations",
    icon: <Wrench className="h-5 w-5 text-success" />,
    title: "Suggest Remediations",
    description: "AI-generated fix recommendations with code patches.",
    prompt: "Suggest specific remediation actions and code patches for the top 5 open vulnerabilities in the current workspace.",
  },
];

// ─── Sub-components ───────────────────────────────────────────────────────────

function ModelSelector({
  selected,
  onChange,
}: {
  selected: ModelId;
  onChange: (id: ModelId) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = MODELS.find((m) => m.id === selected)!;

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground transition-colors hover:bg-accent"
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <Cpu className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-medium">{current.label}</span>
        <span className="text-xs text-muted-foreground">{current.provider}</span>
        <ChevronDown className={cn("h-3.5 w-3.5 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div className="absolute left-0 top-full z-50 mt-1 min-w-[160px] rounded-xl border border-border bg-popover py-1 shadow-xl">
          {MODELS.map((model) => (
            <button
              key={model.id}
              role="option"
              aria-selected={model.id === selected}
              onClick={() => { onChange(model.id); setOpen(false); }}
              className={cn(
                "flex w-full items-center gap-3 px-3 py-2 text-sm transition-colors hover:bg-accent",
                model.id === selected && "text-primary"
              )}
            >
              <span className="font-medium">{model.label}</span>
              <span className="ml-auto text-xs text-muted-foreground">{model.provider}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ChatMessage({ message }: { message: Message }) {
  const isUser = message.role === "user";
  return (
    <div className={cn("flex items-start gap-3", isUser && "flex-row-reverse")}>
      <div className={cn(
        "flex h-7 w-7 shrink-0 items-center justify-center rounded-full",
        isUser ? "bg-primary/20" : "bg-secondary"
      )}>
        {isUser
          ? <User className="h-4 w-4 text-primary" />
          : <Bot className="h-4 w-4 text-muted-foreground" />
        }
      </div>
      <div className={cn(
        "max-w-[80%] rounded-xl px-4 py-2.5 text-sm",
        isUser
          ? "rounded-tr-sm bg-primary/15 text-foreground"
          : "rounded-tl-sm bg-card text-foreground border border-border/50"
      )}>
        <p className="leading-relaxed">{message.content}</p>
        <p className="mt-1 text-right text-[10px] text-muted-foreground/70">
          {message.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </p>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CopilotDashboard() {
  const [model, setModel] = useState<ModelId>("gpt-4o");
  const [inputValue, setInputValue] = useState("");
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      content:
        "AI Copilot is ready. I have access to your current workspace findings, active threats, and compliance status. How can I assist you?",
      timestamp: new Date(),
    },
  ]);
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isTyping]);

  function sendMessage(content: string) {
    if (!content.trim()) return;

    const userMsg: Message = {
      id: `user-${Date.now()}`,
      role: "user",
      content: content.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue("");
    setIsTyping(true);

    // Simulate async response (replace with actual API call)
    setTimeout(() => {
      const assistantMsg: Message = {
        id: `assistant-${Date.now()}`,
        role: "assistant",
        content:
          "This is a placeholder response. Connect the AI Copilot service endpoint to enable live model inference.",
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
      setIsTyping(false);
    }, 1200);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(inputValue);
    }
  }

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* ── Page Header ── */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Bot className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-semibold text-foreground">AI Copilot</h1>
            <Badge variant="new">BETA</Badge>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Enterprise AI assistant for security operations, threat analysis, and automated remediation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ModelSelector selected={model} onChange={setModel} />
        </div>
      </div>

      {/* ── Context Strip ── */}
      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Workspace:</span>
          <span>prod-us-east-1</span>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Active Findings:</span>
          <span className="text-destructive font-semibold">247</span>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Model:</span>
          <span>{MODELS.find((m) => m.id === model)?.label}</span>
        </div>
      </div>

      {/* ── Quick Actions Grid ── */}
      <div>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-widest text-muted-foreground">
          Quick Actions
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {QUICK_ACTIONS.map((action) => (
            <Card
              key={action.id}
              className="cursor-pointer transition-all duration-150 hover:border-primary/40 hover:shadow-lg"
              onClick={() => sendMessage(action.prompt)}
            >
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  {action.icon}
                  <CardTitle className="text-sm">{action.title}</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground">{action.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* ── Chat Interface ── */}
      <Card className="flex flex-col" style={{ height: "420px" }}>
        <CardHeader className="shrink-0 border-b border-border/50 py-3">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-success" />
            <CardTitle className="text-sm">Conversation</CardTitle>
          </div>
        </CardHeader>

        {/* Messages */}
        <CardContent className="flex flex-1 flex-col gap-4 overflow-y-auto py-4">
          {messages.map((msg) => (
            <ChatMessage key={msg.id} message={msg} />
          ))}
          {isTyping && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>AI Copilot is thinking…</span>
            </div>
          )}
          <div ref={messagesEndRef} />
        </CardContent>

        {/* Input */}
        <div className="shrink-0 border-t border-border/50 p-4">
          <div className="flex items-center gap-2">
            <Input
              placeholder="Ask about threats, findings, compliance, remediations…"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1"
              disabled={isTyping}
            />
            <Button
              size="icon"
              onClick={() => sendMessage(inputValue)}
              disabled={isTyping || !inputValue.trim()}
              aria-label="Send message"
            >
              <Send className="h-4 w-4" />
            </Button>
          </div>
          <p className="mt-1.5 text-[11px] text-muted-foreground/60">
            AI responses are advisory only. Validate all recommendations before taking action.
          </p>
        </div>
      </Card>
    </div>
  );
}
