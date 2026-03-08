import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import {
  MessageSquare, Users, Link2, Paperclip, CheckSquare, Plus,
  Send, Clock, AlertTriangle, CheckCircle2, Flame, User
} from "lucide-react";
import { remediationApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
interface WarRoom {
  id: string;
  name: string;
  status: "active" | "resolved" | "escalated";
  severity: "Critical" | "High" | "Medium";
  participants: number;
  linkedFindings: number;
  lastActivity: string;
  createdAt: string;
  description: string;
  lead: string;
}

interface Message {
  id: string;
  author: string;
  authorInitials: string;
  authorColor: string;
  content: string;
  timestamp: string;
  type: "message" | "system" | "finding_linked";
}

interface ActionItem {
  id: string;
  text: string;
  done: boolean;
  assignee: string;
  dueDate: string;
}

interface Attachment {
  id: string;
  name: string;
  type: "screenshot" | "log" | "report" | "pcap";
  size: string;
  uploadedBy: string;
  uploadedAt: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_WAR_ROOMS: WarRoom[] = [
  { id: "wr-1", name: "Log4Shell Incident Response",     status: "active",    severity: "Critical", participants: 8,  linkedFindings: 3, lastActivity: "2m ago",   createdAt: "09:15 today", description: "Active response to Log4Shell in logging-service", lead: "Sophia Chen" },
  { id: "wr-2", name: "Payment SSRF Investigation",      status: "active",    severity: "Critical", participants: 5,  linkedFindings: 2, lastActivity: "15m ago",  createdAt: "11:30 today", description: "SSRF vulnerability affecting payment processing",   lead: "Arjun Patel" },
  { id: "wr-3", name: "Prometheus Unauth Exposure",      status: "escalated", severity: "High",     participants: 4,  linkedFindings: 1, lastActivity: "1h ago",   createdAt: "Yesterday",   description: "Unauth Prometheus endpoint exposed to internet",  lead: "Lena Müller" },
  { id: "wr-4", name: "Ransomware Tabletop Debrief",     status: "resolved",  severity: "High",     participants: 12, linkedFindings: 0, lastActivity: "2d ago",   createdAt: "3d ago",      description: "Post-exercise debrief and action items",          lead: "Rachel Okafor" },
];

const MOCK_MESSAGES: Message[] = [
  { id: "m-1",  author: "Sophia Chen",   authorInitials: "SC", authorColor: "bg-purple-500", content: "War room opened. Log4Shell CVE-2021-44228 confirmed in logging-service:2.14.1", timestamp: "09:15", type: "system" },
  { id: "m-2",  author: "Arjun Patel",   authorInitials: "AP", authorColor: "bg-blue-500",   content: "Blast radius check complete — 3 downstream services calling logging-service. All affected.", timestamp: "09:22", type: "message" },
  { id: "m-3",  author: "System",        authorInitials: "SY", authorColor: "bg-muted",      content: "FIND-8821 linked to this war room", timestamp: "09:23", type: "finding_linked" },
  { id: "m-4",  author: "Lena Müller",   authorInitials: "LM", authorColor: "bg-teal-500",   content: "I can take lead on the patch deployment. Upgrading log4j-core to 2.17.2. ETA 1h.", timestamp: "09:31", type: "message" },
  { id: "m-5",  author: "James Kim",     authorInitials: "JK", authorColor: "bg-orange-500", content: "JIRA SEC-1284 created. Notified business owner. They've acknowledged, 24h SLA clock started.", timestamp: "09:45", type: "message" },
  { id: "m-6",  author: "Sophia Chen",   authorInitials: "SC", authorColor: "bg-purple-500", content: "Temporary WAF rule deployed to block JNDI payloads while we patch. Monitoring Kibana for hits.", timestamp: "10:02", type: "message" },
  { id: "m-7",  author: "Rachel Okafor", authorInitials: "RO", authorColor: "bg-green-500",  content: "PR #447 raised: autofix/log4j-upgrade-8821. SAST passed. Requesting review from @arjun", timestamp: "10:44", type: "message" },
  { id: "m-8",  author: "Arjun Patel",   authorInitials: "AP", authorColor: "bg-blue-500",   content: "PR reviewed and approved. Merging to main, deploying to staging now.", timestamp: "11:01", type: "message" },
];

const MOCK_ACTION_ITEMS: ActionItem[] = [
  { id: "ai-1", text: "Upgrade log4j-core to 2.17.2 in logging-service", done: true,  assignee: "Lena Müller",  dueDate: "Today EOD" },
  { id: "ai-2", text: "Deploy temporary WAF rule to block JNDI payloads", done: true,  assignee: "Sophia Chen", dueDate: "Today EOD" },
  { id: "ai-3", text: "Verify patch in staging environment",              done: false, assignee: "Arjun Patel",  dueDate: "Today EOD" },
  { id: "ai-4", text: "Deploy to production with rollback plan ready",    done: false, assignee: "Lena Müller",  dueDate: "Tomorrow EOD" },
  { id: "ai-5", text: "Remove WAF rule after production deploy verified",  done: false, assignee: "Sophia Chen", dueDate: "Tomorrow EOD" },
  { id: "ai-6", text: "Incident post-mortem and RCA document",            done: false, assignee: "Rachel Okafor", dueDate: "+3 days" },
];

const MOCK_ATTACHMENTS: Attachment[] = [
  { id: "att-1", name: "blast-radius-analysis.pdf",     type: "report",     size: "1.2 MB", uploadedBy: "Arjun Patel",   uploadedAt: "09:22" },
  { id: "att-2", name: "jndi-payload-kibana-screenshot.png", type: "screenshot", size: "342 KB", uploadedBy: "Sophia Chen",  uploadedAt: "10:05" },
  { id: "att-3", name: "affected-services-log-dump.log", type: "log",        size: "8.4 MB", uploadedBy: "James Kim",     uploadedAt: "10:15" },
  { id: "att-4", name: "network-capture-jndi.pcap",      type: "pcap",       size: "2.1 MB", uploadedBy: "Lena Müller",  uploadedAt: "10:44" },
];

const LINKED_FINDINGS = [
  { id: "FIND-8821", title: "Log4Shell in logging-service",    severity: "Critical" },
  { id: "FIND-8820", title: "Downstream: order-svc affected",  severity: "Critical" },
  { id: "FIND-8819", title: "Downstream: report-svc affected", severity: "High" },
];

const severityConfig: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const roomStatusConfig = {
  active:    "bg-green-500/10 text-green-400 border-green-500/30",
  escalated: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  resolved:  "bg-muted text-muted-foreground border-border",
};

const attachTypeIcon = {
  screenshot: "🖼",
  log:        "📄",
  report:     "📊",
  pcap:       "🔬",
};

// ── Main Component ─────────────────────────────────────────────────────────
export default function Collaboration() {
  const [selectedRoom, setSelectedRoom] = useState<WarRoom>(MOCK_WAR_ROOMS[0]);
  const [newMessage, setNewMessage] = useState("");
  const [actionItems, setActionItems] = useState<ActionItem[]>(MOCK_ACTION_ITEMS);

  const { data } = useQuery({
    queryKey: ["war-rooms"],
    queryFn: () => remediationApi.list({ type: "war_rooms" }),
    refetchInterval: 20_000,
  });

  const rooms: WarRoom[] = (data as any)?.data ?? MOCK_WAR_ROOMS;
  const activeCount = rooms.filter(r => r.status === "active").length;
  const doneItems = actionItems.filter(a => a.done).length;

  const sendMessage = () => {
    if (!newMessage.trim()) return;
    toast.success("Message sent");
    setNewMessage("");
  };

  const toggleAction = (id: string) => {
    setActionItems(prev => prev.map(a => a.id === id ? { ...a, done: !a.done } : a));
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Collaboration"
        description="War Rooms — coordinated response spaces for active security incidents"
        badge="REMEDIATE"
        actions={
          <Button size="sm">
            <Plus className="h-3.5 w-3.5 mr-1.5" /> New War Room
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active War Rooms" value={activeCount} icon={Flame} trend="flat" />
        <KpiCard title="Participants" value={rooms.reduce((s, r) => s + r.participants, 0)} icon={Users} trend="flat" />
        <KpiCard title="Linked Findings" value={rooms.reduce((s, r) => s + r.linkedFindings, 0)} icon={Link2} trend="flat" />
        <KpiCard title="Actions Done" value={`${doneItems}/${actionItems.length}`} icon={CheckSquare} trend="up" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* War Room List */}
        <div className="space-y-2">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Flame className="h-4 w-4 text-primary" /> War Rooms
          </h3>
          {rooms.map(room => (
            <Card
              key={room.id}
              className={`border-border/50 cursor-pointer transition-all hover:border-primary/40 ${selectedRoom.id === room.id ? "border-primary/60 bg-primary/5" : ""}`}
              onClick={() => setSelectedRoom(room)}
            >
              <CardContent className="p-3 space-y-2">
                <div className="flex items-start justify-between gap-1.5">
                  <p className="text-sm font-medium line-clamp-1">{room.name}</p>
                  <span className={`shrink-0 inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${roomStatusConfig[room.status]}`}>{room.status}</span>
                </div>
                <div className="flex gap-2 text-xs text-muted-foreground">
                  <span className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${severityConfig[room.severity]}`}>{room.severity}</span>
                  <span className="flex items-center gap-1"><Users className="h-3 w-3" /> {room.participants}</span>
                  <span className="flex items-center gap-1"><Link2 className="h-3 w-3" /> {room.linkedFindings}</span>
                </div>
                <p className="text-[10px] text-muted-foreground flex items-center gap-1">
                  <Clock className="h-2.5 w-2.5" /> {room.lastActivity}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Room Detail */}
        <div className="xl:col-span-3 space-y-4">
          {/* Room header */}
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-base font-bold">{selectedRoom.name}</h2>
                    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${roomStatusConfig[selectedRoom.status]}`}>{selectedRoom.status}</span>
                    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[selectedRoom.severity]}`}>{selectedRoom.severity}</span>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">{selectedRoom.description}</p>
                </div>
                <div className="text-right shrink-0 text-xs text-muted-foreground">
                  <p>Lead: {selectedRoom.lead}</p>
                  <p>{selectedRoom.participants} participants</p>
                  <p>Opened {selectedRoom.createdAt}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Discussion Thread */}
            <div className="lg:col-span-2 space-y-2">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <MessageSquare className="h-3.5 w-3.5" /> Discussion
              </h3>
              <Card className="border-border/50">
                <CardContent className="p-3 space-y-3 max-h-64 overflow-y-auto">
                  {MOCK_MESSAGES.map(msg => (
                    <div key={msg.id} className={`flex gap-2.5 ${msg.type === "system" || msg.type === "finding_linked" ? "opacity-60" : ""}`}>
                      <div className={`h-6 w-6 rounded-full shrink-0 flex items-center justify-center text-white text-[9px] font-bold ${msg.authorColor}`}>
                        {msg.authorInitials}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold">{msg.author}</span>
                          <span className="text-[10px] text-muted-foreground">{msg.timestamp}</span>
                          {msg.type === "finding_linked" && <Badge variant="outline" className="text-[9px] h-4">system</Badge>}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">{msg.content}</p>
                      </div>
                    </div>
                  ))}
                </CardContent>
                <div className="border-t border-border/50 p-3 flex gap-2">
                  <Input placeholder="Add message..." value={newMessage} onChange={e => setNewMessage(e.target.value)}
                    className="text-xs h-8" onKeyDown={e => e.key === "Enter" && sendMessage()} />
                  <Button size="sm" className="h-8 shrink-0" onClick={sendMessage}>
                    <Send className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </Card>

              {/* Attachments */}
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5 mt-3">
                <Paperclip className="h-3.5 w-3.5" /> Attachments
              </h3>
              <div className="grid grid-cols-2 gap-2">
                {MOCK_ATTACHMENTS.map(att => (
                  <div key={att.id} className="flex items-center gap-2 rounded-lg border border-border/50 p-2 hover:border-primary/30 transition-colors cursor-pointer">
                    <span className="text-base">{attachTypeIcon[att.type]}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate">{att.name}</p>
                      <p className="text-[10px] text-muted-foreground">{att.size} · {att.uploadedAt}</p>
                    </div>
                  </div>
                ))}
                <Button variant="outline" size="sm" className="h-auto py-3 border-dashed text-xs" onClick={() => toast.info("Upload attachment")}>
                  <Plus className="h-3 w-3 mr-1" /> Upload
                </Button>
              </div>
            </div>

            {/* Right panel */}
            <div className="space-y-3">
              {/* Linked Findings */}
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Link2 className="h-3.5 w-3.5" /> Linked Findings
              </h3>
              <div className="space-y-1.5">
                {LINKED_FINDINGS.map(f => (
                  <div key={f.id} className="flex items-center gap-2 rounded-lg border border-border/50 p-2">
                    <span className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium shrink-0 ${severityConfig[f.severity]}`}>{f.severity}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate">{f.title}</p>
                      <p className="text-[10px] font-mono text-muted-foreground">{f.id}</p>
                    </div>
                  </div>
                ))}
                <Button variant="outline" size="sm" className="w-full h-7 text-xs border-dashed" onClick={() => toast.info("Link finding")}>
                  <Plus className="h-3 w-3 mr-1" /> Link Finding
                </Button>
              </div>

              {/* Action Checklist */}
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5 mt-3">
                <CheckSquare className="h-3.5 w-3.5" /> Action Checklist
              </h3>
              <Card className="border-border/50">
                <CardContent className="p-3 space-y-2">
                  <div className="flex items-center justify-between text-xs text-muted-foreground mb-2">
                    <span>{doneItems}/{actionItems.length} done</span>
                    <span>{Math.round((doneItems / actionItems.length) * 100)}%</span>
                  </div>
                  <Progress value={(doneItems / actionItems.length) * 100} className="h-1.5 mb-3" />
                  {actionItems.map(item => (
                    <div key={item.id} className="flex items-start gap-2">
                      <input
                        type="checkbox" checked={item.done}
                        onChange={() => toggleAction(item.id)}
                        className="mt-0.5 rounded accent-primary shrink-0"
                      />
                      <div className="flex-1 min-w-0">
                        <p className={`text-xs ${item.done ? "line-through text-muted-foreground" : ""}`}>{item.text}</p>
                        <p className="text-[10px] text-muted-foreground">{item.assignee} · {item.dueDate}</p>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
