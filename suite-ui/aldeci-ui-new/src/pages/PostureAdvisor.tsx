/**
 * Security Posture Advisor — CTO Virtual Advisor Page
 *
 * AI-powered security posture recommendations with:
 *   1. Current Posture Score — circular progress gauge (SVG)
 *   2. Improvement Roadmap — 3-phase timeline with Quick Wins, Medium Term, Strategic
 *   3. Active Recommendations — table with priority, effort, score_impact
 *   4. Category Breakdown — radar chart (static SVG polygon)
 *
 * API: GET /api/v1/posture-advisor/analyze, /api/v1/posture-advisor/roadmap
 * Fallback: mock data when API is unavailable
 */

import { useState, useCallback, JSX } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  ShieldCheck, AlertTriangle, CheckCircle2, TrendingUp,
  Zap, Clock, Target, BarChart3, RefreshCw, ThumbsUp, X,
  Cpu, Lock, Network, Shield, HardDrive, Users, Gauge, Eye,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type Priority = "Critical" | "High" | "Medium" | "Low";
type Effort = "Quick" | "Medium" | "High";
type Phase = "Quick Wins" | "Medium Term" | "Strategic";

interface Recommendation {
  id: string;
  title: string;
  category: string;
  priority: Priority;
  effort: Effort;
  score_impact: number;
  description: string;
  phase: Phase;
}

interface RoadmapPhase {
  phase: Phase;
  days_range: string;
  count: number;
  estimated_score_gain: number;
  recommendations: Recommendation[];
}

interface PostureData {
  current_score: number;
  max_score: number;
  recommendations: Recommendation[];
  roadmap: RoadmapPhase[];
  categories: Record<string, { count: number; impact: number }>;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_POSTURE_DATA: PostureData = {
  current_score: 62,
  max_score: 100,
  recommendations: [
    {
      id: "r1",
      title: "Enforce MFA for all users",
      category: "Identity & Access",
      priority: "Critical",
      effort: "Quick",
      score_impact: 8,
      description: "Require multi-factor authentication for all user accounts to prevent credential compromise.",
      phase: "Quick Wins",
    },
    {
      id: "r2",
      title: "Establish patch cadence",
      category: "Asset Management",
      priority: "Critical",
      effort: "Medium",
      score_impact: 9,
      description: "Define and implement a monthly security patch schedule for all systems.",
      phase: "Quick Wins",
    },
    {
      id: "r3",
      title: "Segment network by trust zones",
      category: "Network Security",
      priority: "High",
      effort: "High",
      score_impact: 12,
      description: "Implement network segmentation to isolate critical systems and reduce lateral movement.",
      phase: "Strategic",
    },
    {
      id: "r4",
      title: "Deploy EDR across all endpoints",
      category: "Endpoint Security",
      priority: "High",
      effort: "High",
      score_impact: 10,
      description: "Install and configure Endpoint Detection & Response solution on all workstations and servers.",
      phase: "Medium Term",
    },
    {
      id: "r5",
      title: "Test backup restoration quarterly",
      category: "Data Resilience",
      priority: "High",
      effort: "Quick",
      score_impact: 7,
      description: "Validate backup integrity and recovery procedures every 90 days.",
      phase: "Quick Wins",
    },
    {
      id: "r6",
      title: "Deliver security awareness training",
      category: "People & Process",
      priority: "Medium",
      effort: "Medium",
      score_impact: 5,
      description: "Mandatory annual security training for all employees with phishing simulations.",
      phase: "Medium Term",
    },
    {
      id: "r7",
      title: "Tune SIEM detection rules",
      category: "Detection & Response",
      priority: "High",
      effort: "Medium",
      score_impact: 8,
      description: "Review and optimize SIEM detection rules to reduce alert fatigue and improve signal quality.",
      phase: "Medium Term",
    },
    {
      id: "r8",
      title: "Conduct privileged access reviews",
      category: "Identity & Access",
      priority: "Medium",
      effort: "Medium",
      score_impact: 6,
      description: "Quarterly review and cleanup of privileged accounts and permissions.",
      phase: "Medium Term",
    },
  ],
  roadmap: [
    {
      phase: "Quick Wins",
      days_range: "0-30 days",
      count: 3,
      estimated_score_gain: 20,
      recommendations: [],
    },
    {
      phase: "Medium Term",
      days_range: "30-90 days",
      count: 4,
      estimated_score_gain: 27,
      recommendations: [],
    },
    {
      phase: "Strategic",
      days_range: "90+ days",
      count: 1,
      estimated_score_gain: 12,
      recommendations: [],
    },
  ],
  categories: {
    "Identity & Access": { count: 2, impact: 14 },
    "Asset Management": { count: 1, impact: 9 },
    "Network Security": { count: 1, impact: 12 },
    "Endpoint Security": { count: 1, impact: 10 },
    "Data Resilience": { count: 1, impact: 7 },
    "People & Process": { count: 1, impact: 5 },
    "Detection & Response": { count: 1, impact: 8 },
  },
};

// ══════════════════════════════════════════════════════════════
// SVG Components
// ══════════════════════════════════════════════════════════════

/**
 * Circular Progress Gauge (SVG stroke-dasharray)
 */
const CircularGauge = ({ score, maxScore }: { score: number; maxScore: number }): JSX.Element => {
  const percentage = (score / maxScore) * 100;
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const getColor = () => {
    if (percentage >= 80) return "#10b981"; // emerald
    if (percentage >= 60) return "#f59e0b"; // amber
    return "#ef4444"; // red
  };

  return (
    <div className="flex flex-col items-center justify-center">
      <svg width="200" height="200" className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx="100"
          cy="100"
          r="45"
          fill="none"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="8"
        />
        {/* Progress circle */}
        <circle
          cx="100"
          cy="100"
          r="45"
          fill="none"
          stroke={getColor()}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: "all 0.3s ease-in-out" }}
        />
      </svg>
      <div className="absolute text-center">
        <div className="text-4xl font-bold text-white">{score}</div>
        <div className="text-sm text-gray-400">/ {maxScore}</div>
      </div>
    </div>
  );
};

/**
 * Radar Chart (Static SVG polygon)
 * 7 categories plotted on a heptagon
 */
const RadarChart = ({ categories }: { categories: Record<string, { count: number; impact: number }> }): JSX.Element => {
  const categoryNames = Object.keys(categories);
  const numCategories = categoryNames.length;
  const maxValue = 15; // Scale for impact
  const radius = 120;
  const centerX = 150;
  const centerY = 150;

  // Calculate points for the outer hexagon/heptagon
  const getPoint = (index: number, distance: number) => {
    const angle = (index / numCategories) * Math.PI * 2 - Math.PI / 2;
    const x = centerX + distance * Math.cos(angle);
    const y = centerY + distance * Math.sin(angle);
    return `${x},${y}`;
  };

  // Web grid lines
  const gridLevels = 5;
  const gridLines = [];
  for (let level = 1; level <= gridLevels; level++) {
    const gridRadius = (level / gridLevels) * radius;
    let points = "";
    for (let i = 0; i <= numCategories; i++) {
      points += getPoint(i, gridRadius) + " ";
    }
    gridLines.push(points);
  }

  // Data points
  const dataPoints = categoryNames
    .map((cat, idx) => {
      const value = (categories[cat].impact / maxValue) * radius;
      return getPoint(idx, value);
    })
    .join(" ");

  // Axis lines
  const axisLines = categoryNames.map((_, idx) => {
    const outerPoint = getPoint(idx, radius);
    return `${centerX},${centerY} ${outerPoint}`;
  });

  return (
    <svg width="300" height="300" viewBox="0 0 300 300" className="mx-auto">
      {/* Grid */}
      {gridLines.map((points, idx) => (
        <polygon
          key={`grid-${idx}`}
          points={points}
          fill="none"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="1"
        />
      ))}

      {/* Axis lines */}
      {axisLines.map((line, idx) => (
        <line
          key={`axis-${idx}`}
          x1={line.split(" ")[0]}
          y1={line.split(" ")[1]}
          x2={line.split(" ")[2]}
          y2={line.split(" ")[3]}
          stroke="rgba(255,255,255,0.2)"
          strokeWidth="1"
        />
      ))}

      {/* Data polygon */}
      <polygon
        points={dataPoints}
        fill="rgba(59, 130, 246, 0.2)"
        stroke="rgba(59, 130, 246, 0.8)"
        strokeWidth="2"
      />

      {/* Data points */}
      {categoryNames.map((_, idx) => {
        const point = getPoint(idx, (categories[categoryNames[idx]].impact / maxValue) * radius);
        const [x, y] = point.split(",").map(Number);
        return (
          <circle
            key={`point-${idx}`}
            cx={x}
            cy={y}
            r="4"
            fill="rgba(59, 130, 246, 0.8)"
            stroke="white"
            strokeWidth="1"
          />
        );
      })}

      {/* Labels */}
      {categoryNames.map((cat, idx) => {
        const labelRadius = radius + 30;
        const angle = (idx / numCategories) * Math.PI * 2 - Math.PI / 2;
        const x = centerX + labelRadius * Math.cos(angle);
        const y = centerY + labelRadius * Math.sin(angle);
        return (
          <text
            key={`label-${idx}`}
            x={x}
            y={y}
            textAnchor="middle"
            dominantBaseline="middle"
            className="fill-gray-300 text-xs font-medium"
            style={{ pointerEvents: "none" }}
          >
            {cat.split(" ")[0]}
          </text>
        );
      })}
    </svg>
  );
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function priorityColor(priority: Priority): string {
  const map: Record<Priority, string> = {
    Critical: "bg-red-500/15 text-red-400 border-red-500/30",
    High: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    Medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    Low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return map[priority];
}

function effortBadgeColor(effort: Effort): string {
  const map: Record<Effort, string> = {
    Quick: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    Medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    High: "bg-red-500/15 text-red-400 border-red-500/30",
  };
  return map[effort];
}

function priorityIcon(priority: Priority) {
  const map: Record<Priority, JSX.Element> = {
    Critical: <AlertTriangle className="w-4 h-4" />,
    High: <AlertTriangle className="w-4 h-4" />,
    Medium: <AlertTriangle className="w-4 h-4" />,
    Low: <Gauge className="w-4 h-4" />,
  };
  return map[priority];
}

function categoryIcon(category: string) {
  const map: Record<string, JSX.Element> = {
    "Identity & Access": <Lock className="w-4 h-4" />,
    "Asset Management": <Cpu className="w-4 h-4" />,
    "Network Security": <Network className="w-4 h-4" />,
    "Endpoint Security": <Shield className="w-4 h-4" />,
    "Data Resilience": <HardDrive className="w-4 h-4" />,
    "People & Process": <Users className="w-4 h-4" />,
    "Detection & Response": <Eye className="w-4 h-4" />,
  };
  return map[category] || <Target className="w-4 h-4" />;
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function PostureAdvisor() {
  const [dismissedRecommendations, setDismissedRecommendations] = useState<Set<string>>(
    new Set()
  );
  const [acceptedRecommendations, setAcceptedRecommendations] = useState<Set<string>>(
    new Set()
  );

  // Fetch posture data
  const { data: postureData, isLoading } = useQuery<PostureData>({
    queryKey: ["posture-advisor"],
    queryFn: async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/posture-advisor/analyze?org_id=default`);
        if (!response.ok) throw new Error("Failed to fetch");
        return await response.json();
      } catch {
        return MOCK_POSTURE_DATA;
      }
    },
    staleTime: 5 * 60 * 1000,
  });

  const handleAccept = useCallback((id: string) => {
    setAcceptedRecommendations((prev) => new Set([...prev, id]));
  }, []);

  const handleDismiss = useCallback((id: string) => {
    setDismissedRecommendations((prev) => new Set([...prev, id]));
  }, []);

  if (isLoading) return <PageSkeleton />;

  const data: PostureData = postureData || MOCK_POSTURE_DATA;
  const activeRecommendations = data.recommendations.filter(
    (r: Recommendation) => !dismissedRecommendations.has(r.id) && !acceptedRecommendations.has(r.id)
  );

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <PageHeader
        title="Security Posture Advisor"
        description="AI-powered improvement recommendations from your virtual CISO"
      />

      {/* ── Current Posture Score ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-blue-400" />
              Current Security Posture
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between gap-8">
              <div className="flex-1 flex justify-center">
                <div className="relative w-[200px] h-[200px]">
                  <CircularGauge score={data.current_score} maxScore={data.max_score} />
                </div>
              </div>

              <div className="flex-1 space-y-4">
                <div>
                  <p className="text-gray-400 text-sm mb-2">Score Breakdown</p>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-300">Current</span>
                      <span className="text-emerald-400 font-semibold">{data.current_score}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-300">Potential Gain</span>
                      <span className="text-blue-400 font-semibold">
                        +{data.max_score - data.current_score}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-300">Target Score</span>
                      <span className="text-amber-400 font-semibold">{data.max_score}</span>
                    </div>
                  </div>
                </div>

                <Separator className="bg-slate-700/50" />

                <div>
                  <p className="text-gray-400 text-sm mb-2">Top Opportunities</p>
                  <div className="space-y-1 text-sm">
                    {data.recommendations
                      .sort((a: Recommendation, b: Recommendation) => b.score_impact - a.score_impact)
                      .slice(0, 3)
                      .map((rec: Recommendation) => (
                        <div key={rec.id} className="flex justify-between">
                          <span className="text-gray-300">{rec.title}</span>
                          <span className="text-blue-400 font-semibold">+{rec.score_impact}</span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Improvement Roadmap ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="w-5 h-5 text-amber-400" />
              Improvement Roadmap
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              {data.roadmap.map((roadmapPhase: RoadmapPhase, idx: number) => (
                <motion.div
                  key={roadmapPhase.phase}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.3 + idx * 0.1 }}
                >
                  <Card className="bg-slate-800/50 border-slate-700 hover:border-slate-600 transition-colors">
                    <CardContent className="pt-6">
                      <div className="space-y-3">
                        {/* Phase title and days */}
                        <div>
                          <h3 className="font-semibold text-white">{roadmapPhase.phase}</h3>
                          <p className="text-xs text-gray-400">{roadmapPhase.days_range}</p>
                        </div>

                        {/* Count badge */}
                        <Badge
                          variant="outline"
                          className="bg-blue-500/10 text-blue-400 border-blue-500/30"
                        >
                          {roadmapPhase.count} recommendation{roadmapPhase.count !== 1 ? "s" : ""}
                        </Badge>

                        {/* Score gain */}
                        <div className="pt-2 border-t border-slate-700/50">
                          <p className="text-xs text-gray-400 mb-1">Score Impact</p>
                          <p className="text-lg font-bold text-emerald-400">
                            +{roadmapPhase.estimated_score_gain}
                          </p>
                        </div>

                        {/* Effort estimate */}
                        <div>
                          <p className="text-xs text-gray-400 mb-1">Estimated Effort</p>
                          <Badge
                            variant="outline"
                            className={cn(
                              "border",
                              idx === 0
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                : idx === 1
                                  ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                                  : "bg-red-500/10 text-red-400 border-red-500/30"
                            )}
                          >
                            {idx === 0 ? "Quick" : idx === 1 ? "Medium" : "High"}
                          </Badge>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Active Recommendations Table ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-yellow-400" />
                Active Recommendations
              </span>
              <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                {activeRecommendations.length} active
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {activeRecommendations.length === 0 ? (
              <div className="text-center py-12">
                <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-3 opacity-50" />
                <p className="text-gray-400">
                  {dismissedRecommendations.size > 0 || acceptedRecommendations.size > 0
                    ? "All remaining recommendations addressed!"
                    : "No active recommendations"}
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-slate-700/50 hover:bg-slate-800/20">
                      <TableHead className="text-gray-300">Title</TableHead>
                      <TableHead className="text-gray-300">Category</TableHead>
                      <TableHead className="text-gray-300">Priority</TableHead>
                      <TableHead className="text-gray-300">Effort</TableHead>
                      <TableHead className="text-gray-300 text-right">Score Impact</TableHead>
                      <TableHead className="text-gray-300 text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {activeRecommendations.map((rec: Recommendation) => (
                      <TableRow
                        key={rec.id}
                        className="border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                      >
                        <TableCell>
                          <div>
                            <p className="font-medium text-white">{rec.title}</p>
                            <p className="text-xs text-gray-400 mt-1">{rec.description}</p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {categoryIcon(rec.category)}
                            <span className="text-sm text-gray-300">{rec.category}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={cn("border", priorityColor(rec.priority))}
                          >
                            <span className="flex items-center gap-1">
                              {priorityIcon(rec.priority)}
                              {rec.priority}
                            </span>
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={cn("border", effortBadgeColor(rec.effort))}
                          >
                            {rec.effort}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <span className="font-semibold text-blue-400">+{rec.score_impact}</span>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              className="border-emerald-500/30 hover:bg-emerald-500/10 h-8 w-8 p-0"
                              onClick={() => handleAccept(rec.id)}
                              title="Accept recommendation"
                            >
                              <ThumbsUp className="w-4 h-4 text-emerald-400" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="border-red-500/30 hover:bg-red-500/10 h-8 w-8 p-0"
                              onClick={() => handleDismiss(rec.id)}
                              title="Dismiss recommendation"
                            >
                              <X className="w-4 h-4 text-red-400" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Category Breakdown — Radar Chart ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5 text-indigo-400" />
              Category Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-8">
              {/* Radar chart */}
              <div className="col-span-1 flex justify-center">
                <RadarChart categories={data.categories} />
              </div>

              {/* Legend and stats */}
              <div className="col-span-2 space-y-4">
                <p className="text-gray-400 text-sm mb-4">
                  Security recommendations by domain with estimated impact on overall posture score.
                </p>
                <div className="grid grid-cols-2 gap-4">
                  {Object.entries(data.categories)
                    .sort((a: [string, { count: number; impact: number }], b: [string, { count: number; impact: number }]) => b[1].impact - a[1].impact)
                    .map(([category, categoryData]: [string, { count: number; impact: number }]) => (
                      <div
                        key={category}
                        className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/30 border border-slate-700/50 hover:border-slate-600 transition-colors"
                      >
                        <div className="text-slate-400 mt-1">
                          {categoryIcon(category)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-medium text-white text-sm truncate">
                            {category}
                          </p>
                          <div className="flex items-center gap-4 mt-1">
                            <span className="text-xs text-gray-400">
                              {categoryData.count} recommendation{categoryData.count !== 1 ? "s" : ""}
                            </span>
                            <span className="text-xs font-semibold text-blue-400">
                              +{categoryData.impact} impact
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Info Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
        className="text-center text-sm text-gray-400 pb-4"
      >
        <p>
          Recommendations based on industry best practices (NIST CSF, CIS Controls, OWASP Top 10).
          <br />
          Last updated: {new Date().toLocaleDateString()}
        </p>
      </motion.div>
    </div>
  );
}
