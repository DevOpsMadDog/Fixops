import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Bot, Send, RefreshCw, Cpu, Activity, MessageSquare } from "lucide-react";
import { useCopilotAgents, useCopilotChat } from "@/hooks/use-api";

export default function CopilotDashboard() {
  const [message, setMessage] = useState("");
  const [chatHistory, setChatHistory] = useState<Array<{ role: string; content: string }>>([]);
  const agents = useCopilotAgents();
  const chat = useCopilotChat();
  const refetch = useCallback(() => agents.refetch(), [agents]);

  if (agents.isLoading) return <PageSkeleton />;
  if (agents.isError) return <ErrorState onRetry={refetch} />;

  const agentList = Array.isArray(agents.data) ? agents.data : agents.data?.agents ?? [];

  const handleSend = async () => {
    if (!message.trim()) return;
    const newHistory = [...chatHistory, { role: "user", content: message }];
    setChatHistory(newHistory);
    setMessage("");
    try {
      const result = await chat.mutateAsync({ message: message.trim(), context: {} });
      setChatHistory([...newHistory, { role: "assistant", content: String((result as Record<string, unknown>).response ?? (result as Record<string, unknown>).message ?? JSON.stringify(result)) }]);
    } catch {
      setChatHistory([...newHistory, { role: "assistant", content: "I encountered an error. Please try again." }]);
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="AI Copilot" description="Intelligent security assistant powered by AI" badge="BETA"
        actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <KpiCard title="AI Agents" value={agentList.length} icon={Bot} />
        <KpiCard title="Messages" value={chatHistory.length} icon={MessageSquare} />
        <KpiCard title="Status" value="Online" icon={Cpu} />
      </div>

      {/* Chat Interface */}
      <Card className="flex-1">
        <CardHeader><CardTitle className="text-sm font-medium">Chat with Copilot</CardTitle></CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3 min-h-[300px]">
            <div className="flex-1 space-y-3 overflow-y-auto max-h-[400px]">
              {chatHistory.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">Ask about findings, compliance status, remediation strategies, or anything security-related.</p>}
              {chatHistory.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div className={`rounded-lg px-4 py-2 max-w-[80%] text-sm ${msg.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted"}`}>{msg.content}</div>
                </div>
              ))}
              {chat.isPending && <div className="flex justify-start"><div className="rounded-lg px-4 py-2 bg-muted text-sm animate-pulse">Thinking...</div></div>}
            </div>
            <div className="flex gap-2">
              <Input placeholder="Ask the AI Copilot..." value={message} onChange={(e) => setMessage(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleSend()} className="flex-1" />
              <Button onClick={handleSend} disabled={chat.isPending || !message.trim()}><Send className="h-4 w-4" /></Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Agents */}
      <Card><CardHeader><CardTitle className="text-sm font-medium">AI Agents ({agentList.length})</CardTitle></CardHeader><CardContent>
        {agentList.length > 0 ? <div className="grid gap-3 sm:grid-cols-2">{agentList.map((a: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center gap-3 p-3 rounded-lg border border-border/50"><Bot className="h-5 w-5 text-primary shrink-0" /><div><p className="font-medium text-sm">{String(a.name ?? `Agent ${i + 1}`)}</p><p className="text-xs text-muted-foreground">{String(a.description ?? "")}</p></div></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-4">AI agents will be listed here once configured.</p>}
      </CardContent></Card>
    </div>
  );
}
