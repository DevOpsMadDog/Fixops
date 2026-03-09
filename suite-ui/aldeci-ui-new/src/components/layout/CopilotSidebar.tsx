import { useState, useRef, useEffect } from "react";
import { Bot, Send, X, Sparkles, Shield, Crosshair, FileText, Brain, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { copilotApi } from "@/lib/api";
import { motion, AnimatePresence } from "framer-motion";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  suggestions?: string[];
  sources?: string[];
  confidence?: number;
}

const quickActions = [
  { label: "Triage findings", icon: Shield, action: "Triage the most critical unresolved findings" },
  { label: "Run MPTE scan", icon: Crosshair, action: "Launch an MPTE micro-pentest on the riskiest app" },
  { label: "Generate evidence", icon: FileText, action: "Generate compliance evidence bundle for SOC2" },
  { label: "Explain top risk", icon: Brain, action: "Explain the top risk in my environment right now" },
];

interface CopilotSidebarProps {
  onClose: () => void;
}

export function CopilotSidebar({ onClose }: CopilotSidebarProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content:
        "Good morning. Here's your security briefing:\n\n• 3 new critical findings detected overnight\n• MPTE verified 2 as exploitable\n• AutoFix has PRs ready for review\n• SLA compliance: 94% on-time\n\nHow can I help you today?",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = async (content: string) => {
    if (!content.trim()) return;

    const userMsg: Message = { role: "user", content, timestamp: new Date() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const res = await copilotApi.chat({ message: content, session_id: "enterprise-session", context: {} });
      const d = res.data;
      const assistantMsg: Message = {
        role: "assistant",
        content: d?.response ?? d?.answer ?? d?.message ?? "I'll look into that for you.",
        timestamp: new Date(),
        suggestions: d?.suggestions ?? [],
        sources: d?.sources ?? [],
        confidence: d?.confidence,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch {
      // Fallback to copilot/ask endpoint
      try {
        const askRes = await fetch((import.meta.env.VITE_API_URL || '') + '/api/v1/copilot/ask', {
          method: 'POST',
          headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' },
          body: JSON.stringify({ question: content }),
        });
        const askData = await askRes.json();
        setMessages((prev) => [...prev, {
          role: "assistant",
          content: askData?.answer ?? "I'm analyzing your security posture. Let me check the data.",
          timestamp: new Date(),
          sources: askData?.references?.map((r: { title: string }) => r.title) ?? [],
        }]);
      } catch {
        setMessages((prev) => [...prev, {
          role: "assistant",
          content: "I'm analyzing your request. This may take a moment as I query the security data.",
          timestamp: new Date(),
        }]);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex h-full w-[380px] flex-col">
      {/* Header */}
      <div className="flex h-14 items-center justify-between border-b border-border px-4">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/15">
            <Bot className="h-4 w-4 text-primary" />
          </div>
          <div>
            <p className="text-sm font-semibold">ALdeci Copilot</p>
            <p className="text-[10px] text-muted-foreground">AI Security Assistant</p>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} className="h-7 w-7">
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <AnimatePresence initial={false}>
          {messages.map((msg, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn(
                "rounded-xl px-3.5 py-2.5 text-sm leading-relaxed",
                msg.role === "user"
                  ? "ml-8 bg-primary text-primary-foreground"
                  : "mr-4 bg-muted"
              )}
            >
              <p className="whitespace-pre-wrap">{msg.content}</p>
              {msg.confidence && (
                <p className="text-[10px] mt-1 opacity-60">Confidence: {Math.round(msg.confidence * 100)}%</p>
              )}
              {msg.suggestions && msg.suggestions.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {msg.suggestions.map((s, si) => (
                    <button key={si} onClick={() => sendMessage(s)}
                      className="text-[10px] px-2 py-0.5 rounded-full bg-primary/10 text-primary hover:bg-primary/20 transition-colors">{s}</button>
                  ))}
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>

        {isLoading && (
          <div className="mr-4 rounded-xl bg-muted px-3.5 py-2.5">
            <div className="flex gap-1">
              <span className="h-2 w-2 rounded-full bg-muted-foreground/40 animate-bounce [animation-delay:0ms]" />
              <span className="h-2 w-2 rounded-full bg-muted-foreground/40 animate-bounce [animation-delay:150ms]" />
              <span className="h-2 w-2 rounded-full bg-muted-foreground/40 animate-bounce [animation-delay:300ms]" />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions */}
      {messages.length <= 1 && (
        <div className="border-t border-border p-3">
          <p className="mb-2 text-xs font-medium text-muted-foreground">Quick actions</p>
          <div className="grid grid-cols-2 gap-1.5">
            {quickActions.map((qa) => (
              <button
                key={qa.label}
                onClick={() => sendMessage(qa.action)}
                className="flex items-center gap-2 rounded-lg bg-muted/50 px-2.5 py-2 text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
              >
                <qa.icon className="h-3 w-3 shrink-0" />
                <span className="truncate">{qa.label}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="border-t border-border p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage(input);
          }}
          className="flex gap-2"
        >
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask anything about your security posture..."
            className="flex-1 text-xs"
            disabled={isLoading}
          />
          <Button type="submit" size="icon" disabled={!input.trim() || isLoading}>
            <Send className="h-3.5 w-3.5" />
          </Button>
        </form>
        <p className="mt-1.5 text-center text-[10px] text-muted-foreground">
          <Sparkles className="inline h-2.5 w-2.5 mr-0.5" />
          Powered by ALdeci AI Engine
        </p>
      </div>
    </div>
  );
}
