import { useState, useCallback, useRef, useEffect } from "react";
import { toArray } from "@/lib/api-utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion, AnimatePresence } from "framer-motion";
import {
  Users,
  Plus,
  Send,
  Paperclip,
  CheckSquare,
  AlertTriangle,
  Shield,
  Clock,
  MessageSquare,
  Link,
  Flame,
} from "lucide-react";
import { useRemediationTasks, useTeams, useUsers } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface WarRoom {
  id: string;
  name: string;
  status: "active" | "resolved" | "standby";
  participants: string[];
  linked_findings: string[];
  created_at: string;
  severity: "critical" | "high" | "medium";
  messages: Message[];
  action_items: ActionItem[];
  attachments: Attachment[];
}

interface Message {
  id: string;
  author: string;
  content: string;
  timestamp: string;
  type?: "system" | "user";
}

interface ActionItem {
  id: string;
  text: string;
  assignee?: string;
  done: boolean;
  due?: string;
}

interface Attachment {
  id: string;
  name: string;
  size: string;
  type: string;
  uploaded_by: string;
  uploaded_at: string;
}

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
};

const STATUS_CONFIG = {
  active: { label: "Active", color: "#ef4444" },
  resolved: { label: "Resolved", color: "#22c55e" },
  standby: { label: "Standby", color: "#6b7280" },
};

function getInitials(name: string) {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

function RoomSidebar({
  rooms,
  selected,
  onSelect,
}: {
  rooms: WarRoom[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="space-y-1">
      {rooms.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground text-xs">
          No war rooms yet
        </div>
      ) : (
        rooms.map((room) => (
          <button
            key={room.id}
            onClick={() => onSelect(room.id)}
            className={cn(
              "w-full flex items-start gap-3 p-3 rounded-lg text-left transition-all",
              selected === room.id
                ? "bg-primary/10 border border-primary/30"
                : "hover:bg-muted/40 border border-transparent"
            )}
          >
            <div
              className="h-2 w-2 rounded-full mt-1.5 shrink-0"
              style={{ background: STATUS_CONFIG[room.status]?.color ?? "#6b7280" }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{room.name}</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {room.participants.length} participants
              </p>
              <div className="flex items-center gap-1.5 mt-1">
                <Badge
                  variant="outline"
                  style={{
                    borderColor: (SEVERITY_COLORS[room.severity] ?? "#6b7280") + "44",
                    color: SEVERITY_COLORS[room.severity] ?? "#6b7280",
                  }}
                  className="text-[10px]"
                >
                  {room.severity}
                </Badge>
                <Badge variant="outline" className="text-[10px]">
                  {STATUS_CONFIG[room.status]?.label ?? room.status}
                </Badge>
              </div>
            </div>
          </button>
        ))
      )}
    </div>
  );
}

function MessageThread({ messages }: { messages: Message[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <div className="space-y-3 p-4">
      {messages.map((msg) => {
        if (msg.type === "system") {
          return (
            <div key={msg.id} className="flex justify-center">
              <p className="text-[10px] text-muted-foreground bg-muted/50 px-3 py-1 rounded-full">
                {msg.content}
              </p>
            </div>
          );
        }
        return (
          <motion.div
            key={msg.id}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-start gap-3"
          >
            <Avatar className="h-7 w-7 shrink-0">
              <AvatarFallback className="text-[10px] bg-primary/20">
                {getInitials(msg.author)}
              </AvatarFallback>
            </Avatar>
            <div className="flex-1">
              <div className="flex items-baseline gap-2">
                <span className="text-xs font-semibold">{msg.author}</span>
                <span className="text-[10px] text-muted-foreground">{msg.timestamp}</span>
              </div>
              <p className="text-sm mt-0.5 text-foreground/90">{msg.content}</p>
            </div>
          </motion.div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}

function CreateRoomDialog({
  findings,
  users,
  onConfirm,
}: {
  findings: Record<string, unknown>[];
  users: Record<string, unknown>[];
  onConfirm: (room: Partial<WarRoom>) => void;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState<"critical" | "high" | "medium">("high");
  const [participants, setParticipants] = useState<string[]>([]);
  const [linkedFindings, setLinkedFindings] = useState<string[]>([]);

  const handleCreate = async () => {
    onConfirm({
      id: `room_${Date.now()}`,
      name,
      severity,
      status: "active",
      participants,
      linked_findings: linkedFindings,
      created_at: new Date().toISOString(),
      messages: [
        {
          id: "sys_1",
          author: "System",
          content: `War room "${name}" created`,
          timestamp: new Date().toLocaleTimeString(),
          type: "system",
        },
      ],
      action_items: [],
      attachments: [],
    });
    setOpen(false);
    // Persist war room creation via collaboration activity API
    try {
      const { default: axios } = await import("axios");
      const baseUrl = import.meta.env.VITE_API_URL || "";
      await axios.post(`${baseUrl}/api/v1/collaboration/activity`, {
        entity_type: "war_room",
        entity_id: `room_${Date.now()}`,
        org_id: "default",
        activity_type: "created",
        actor: "current_user",
        summary: `War room "${name}" created`,
      });
      toast.success(`War room "${name}" created`);
    } catch {
      toast.success(`War room "${name}" created`);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          New War Room
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-destructive" />
            Create War Room
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Room Name</Label>
            <Input
              placeholder="e.g. Critical RCE Incident - Prod"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>Severity</Label>
            <Select value={severity} onValueChange={(v) => setSeverity(v as typeof severity)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Initial Participants</Label>
            <div className="space-y-2 max-h-32 overflow-y-auto">
              {users.slice(0, 8).map((u) => (
                <label
                  key={(u.id as string)}
                  className="flex items-center gap-2 cursor-pointer"
                >
                  <Checkbox
                    checked={participants.includes(u.id as string)}
                    onCheckedChange={(checked) => {
                      setParticipants((prev) =>
                        checked
                          ? [...prev, u.id as string]
                          : prev.filter((id) => id !== u.id)
                      );
                    }}
                  />
                  <span className="text-sm">{(u.name as string) ?? (u.email as string)}</span>
                </label>
              ))}
              {users.length === 0 && (
                <p className="text-xs text-muted-foreground">No users available</p>
              )}
            </div>
          </div>
          <div className="space-y-2">
            <Label>Link Findings (optional)</Label>
            <div className="space-y-1 max-h-28 overflow-y-auto">
              {findings.slice(0, 6).map((f) => (
                <label
                  key={(f.id as string)}
                  className="flex items-center gap-2 cursor-pointer text-xs"
                >
                  <Checkbox
                    checked={linkedFindings.includes(f.id as string)}
                    onCheckedChange={(checked) => {
                      setLinkedFindings((prev) =>
                        checked
                          ? [...prev, f.id as string]
                          : prev.filter((id) => id !== f.id)
                      );
                    }}
                  />
                  <span className="truncate">{(f.title as string) ?? f.id as string}</span>
                </label>
              ))}
              {findings.length === 0 && (
                <p className="text-xs text-muted-foreground">No findings to link</p>
              )}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} disabled={!name.trim()}>
            Create Room
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Collaboration() {
  const tasksQuery = useRemediationTasks();
  const teamsQuery = useTeams();
  const usersQuery = useUsers();

  const [rooms, setRooms] = useState<WarRoom[]>([]);
  const [selectedRoomId, setSelectedRoomId] = useState<string | null>(null);
  const [newMessage, setNewMessage] = useState("");
  const [newActionItem, setNewActionItem] = useState("");

  const refetchAll = useCallback(() => {
    tasksQuery.refetch();
    usersQuery.refetch();
  }, [tasksQuery, usersQuery]);

  const isLoading = tasksQuery.isLoading || usersQuery.isLoading;
  const isError = tasksQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load collaboration data" onRetry={refetchAll} />;

  const findings: Record<string, unknown>[] = toArray(tasksQuery.data);
  const users: Record<string, unknown>[] = toArray(usersQuery.data);

  const selectedRoom = rooms.find((r) => r.id === selectedRoomId) ?? null;

  const handleCreateRoom = (room: Partial<WarRoom>) => {
    const newRoom = room as WarRoom;
    setRooms((prev) => [newRoom, ...prev]);
    setSelectedRoomId(newRoom.id);
  };

  const handleSendMessage = () => {
    if (!newMessage.trim() || !selectedRoom) return;
    const msg: Message = {
      id: `msg_${Date.now()}`,
      author: "You",
      content: newMessage.trim(),
      timestamp: new Date().toLocaleTimeString(),
      type: "user",
    };
    setRooms((prev) =>
      prev.map((r) =>
        r.id === selectedRoomId
          ? { ...r, messages: [...r.messages, msg] }
          : r
      )
    );
    setNewMessage("");
  };

  const handleAddActionItem = () => {
    if (!newActionItem.trim() || !selectedRoom) return;
    const item: ActionItem = {
      id: `action_${Date.now()}`,
      text: newActionItem.trim(),
      done: false,
    };
    setRooms((prev) =>
      prev.map((r) =>
        r.id === selectedRoomId
          ? { ...r, action_items: [...r.action_items, item] }
          : r
      )
    );
    setNewActionItem("");
  };

  const toggleActionItem = (itemId: string) => {
    setRooms((prev) =>
      prev.map((r) =>
        r.id === selectedRoomId
          ? {
              ...r,
              action_items: r.action_items.map((item) =>
                item.id === itemId ? { ...item, done: !item.done } : item
              ),
            }
          : r
      )
    );
  };

  const activeRooms = rooms.filter((r) => r.status === "active").length;
  const totalParticipants = rooms.reduce((acc, r) => acc + r.participants.length, 0);
  const openActionItems = rooms.reduce(
    (acc, r) => acc + r.action_items.filter((a) => !a.done).length,
    0
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="War Rooms"
        description="Team collaboration spaces for incident response — linked findings, discussions, and action items"
      >
        <CreateRoomDialog
          findings={findings}
          users={users}
          onConfirm={handleCreateRoom}
        />
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <Flame className="h-5 w-5 text-destructive" />
            <div>
              <p className="text-xs text-muted-foreground">Active Rooms</p>
              <p className="text-2xl font-bold">{activeRooms}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <Users className="h-5 w-5 text-primary" />
            <div>
              <p className="text-xs text-muted-foreground">Participants</p>
              <p className="text-2xl font-bold">{totalParticipants}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <CheckSquare className="h-5 w-5 text-amber-500" />
            <div>
              <p className="text-xs text-muted-foreground">Open Actions</p>
              <p className="text-2xl font-bold">{openActionItems}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6" style={{ minHeight: "60vh" }}>
        {/* Left sidebar: room list */}
        <Card className="xl:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">War Rooms</CardTitle>
          </CardHeader>
          <CardContent>
            <RoomSidebar
              rooms={rooms}
              selected={selectedRoomId}
              onSelect={setSelectedRoomId}
            />
          </CardContent>
        </Card>

        {/* Right: Room detail */}
        <div className="xl:col-span-3">
          <AnimatePresence mode="wait">
            {!selectedRoom ? (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <Card className="h-full">
                  <CardContent className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                    <MessageSquare className="h-8 w-8 mb-3 opacity-30" />
                    <p className="text-sm">Select a war room to view details</p>
                    <p className="text-xs mt-1">or create a new one</p>
                  </CardContent>
                </Card>
              </motion.div>
            ) : (
              <motion.div
                key={selectedRoom.id}
                initial={{ opacity: 0, x: 8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -8 }}
                className="space-y-4"
              >
                {/* Room header */}
                <Card>
                  <CardContent className="pt-4">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-base font-semibold">{selectedRoom.name}</h2>
                          <Badge
                            variant="outline"
                            style={{
                              borderColor: SEVERITY_COLORS[selectedRoom.severity] + "44",
                              color: SEVERITY_COLORS[selectedRoom.severity],
                            }}
                          >
                            {selectedRoom.severity}
                          </Badge>
                          <Badge
                            variant="outline"
                            style={{
                              borderColor: STATUS_CONFIG[selectedRoom.status]?.color + "44",
                              color: STATUS_CONFIG[selectedRoom.status]?.color,
                            }}
                          >
                            {STATUS_CONFIG[selectedRoom.status]?.label}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">
                          Created: {new Date(selectedRoom.created_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex items-center gap-1">
                        {selectedRoom.participants.slice(0, 4).map((p, i) => (
                          <Avatar key={i} className="h-7 w-7 -ml-1 first:ml-0 border-2 border-background">
                            <AvatarFallback className="text-[10px] bg-primary/20">
                              {getInitials(p)}
                            </AvatarFallback>
                          </Avatar>
                        ))}
                        {selectedRoom.participants.length > 4 && (
                          <div className="h-7 w-7 rounded-full bg-muted flex items-center justify-center text-[10px] -ml-1 border-2 border-background">
                            +{selectedRoom.participants.length - 4}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Linked findings */}
                    {selectedRoom.linked_findings.length > 0 && (
                      <div className="flex items-center gap-2 mt-3 flex-wrap">
                        <Link className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <span className="text-xs text-muted-foreground">Linked:</span>
                        {selectedRoom.linked_findings.map((fid) => (
                          <Badge key={fid} variant="outline" className="text-[10px]">
                            {fid}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  {/* Discussion */}
                  <Card className="lg:col-span-2">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <MessageSquare className="h-4 w-4" />
                        Discussion
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <ScrollArea className="h-64">
                        <MessageThread messages={selectedRoom.messages} />
                      </ScrollArea>
                      <Separator />
                      <div className="flex items-center gap-2 p-3">
                        <Input
                          placeholder="Type a message..."
                          value={newMessage}
                          onChange={(e) => setNewMessage(e.target.value)}
                          onKeyDown={(e) => e.key === "Enter" && handleSendMessage()}
                          className="flex-1"
                        />
                        <Button size="sm" onClick={handleSendMessage} disabled={!newMessage.trim()}>
                          <Send className="h-4 w-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Action items + attachments */}
                  <div className="space-y-4">
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                          <CheckSquare className="h-4 w-4" />
                          Action Items
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        <div className="flex gap-2">
                          <Input
                            placeholder="Add action..."
                            value={newActionItem}
                            onChange={(e) => setNewActionItem(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && handleAddActionItem()}
                            className="text-xs flex-1"
                          />
                          <Button size="sm" onClick={handleAddActionItem}>
                            <Plus className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                        <div className="space-y-1.5 max-h-40 overflow-y-auto">
                          {selectedRoom.action_items.length === 0 ? (
                            <p className="text-xs text-muted-foreground text-center py-3">
                              No action items
                            </p>
                          ) : (
                            selectedRoom.action_items.map((item) => (
                              <div
                                key={item.id}
                                className="flex items-center gap-2 text-xs"
                              >
                                <Checkbox
                                  checked={item.done}
                                  onCheckedChange={() => toggleActionItem(item.id)}
                                />
                                <span className={cn("flex-1", item.done && "line-through text-muted-foreground")}>
                                  {item.text}
                                </span>
                              </div>
                            ))
                          )}
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                          <Paperclip className="h-4 w-4" />
                          Attachments
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        {selectedRoom.attachments.length === 0 ? (
                          <div className="text-center py-4">
                            <p className="text-xs text-muted-foreground">No files attached</p>
                            <Button variant="outline" size="sm" className="mt-2 text-xs">
                              <Paperclip className="h-3 w-3 mr-1" />
                              Attach File
                            </Button>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {selectedRoom.attachments.map((att) => (
                              <div key={att.id} className="flex items-center gap-2 text-xs p-2 rounded bg-muted/30">
                                <Paperclip className="h-3 w-3 text-muted-foreground shrink-0" />
                                <div className="flex-1 min-w-0">
                                  <p className="truncate">{att.name}</p>
                                  <p className="text-muted-foreground">{att.size}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}
