# ALdeci UI Design Spec for Page Builders

## Stack
- React 19 + TypeScript strict
- Tailwind CSS 4 (dark mode first)
- shadcn/ui pattern components (import from @/components/ui/)
- Framer Motion for page transitions
- Recharts for charts
- Lucide React for icons
- TanStack Query for data fetching
- Sonner for toasts
- API client at @/lib/api.ts

## Available UI Components (import from @/components/ui/)
- Button (variants: default, destructive, outline, secondary, ghost, link)
- Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter
- Badge (variants: default, secondary, destructive, outline, success, warning, critical, high, medium, low, info, new)
- Input
- Progress
- Tabs, TabsList, TabsTrigger, TabsContent
- Select, SelectTrigger, SelectContent, SelectItem, SelectValue

## Shared Components (import from @/components/shared/)
- KpiCard (title, value, change, changeLabel, icon, trend)
- PageHeader (title, description, badge, actions)
- DataTable (columns, data, onRowClick, emptyMessage)

## Design Rules
1. Dark mode first — all colors use Tailwind dark utilities
2. Apple HIG-inspired: clean typography, generous whitespace, depth via subtle shadows not borders
3. Typography: text-2xl font-bold for page titles, text-sm for body, text-xs for metadata
4. Spacing: use p-5 for card padding, space-y-6 for page sections, gap-4 for grids
5. Every page wraps content in motion.div with initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
6. Use TanStack Query for ALL data fetching — NO raw useEffect+fetch
7. Use Sonner toast() for user feedback
8. Each page must be 200-500 LOC with realistic mock data as fallback
9. Grid layout: use responsive grids (grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4)
10. Every page is a default export

## Page Template
```tsx
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { SomeIcon } from "lucide-react";
import { someApi } from "@/lib/api";
import { toast } from "sonner";

export default function PageName() {
  const { data, isLoading } = useQuery({
    queryKey: ["page-key"],
    queryFn: () => someApi.list(),
  });

  // Use real API data when available, fall back to realistic mock
  const items = data?.data ?? MOCK_DATA;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader title="Page Title" description="Brief description" actions={<Button>Action</Button>} />
      {/* KPI row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Metric" value={42} change={5} trend="up" icon={SomeIcon} />
      </div>
      {/* Content */}
    </motion.div>
  );
}

const MOCK_DATA = [/* realistic enterprise data */];
```

## Color Usage
- Critical severity: text-red-400 bg-red-500/10
- High severity: text-orange-400 bg-orange-500/10
- Medium severity: text-yellow-400 bg-yellow-500/10
- Low severity: text-blue-400 bg-blue-500/10
- Success: text-green-400 bg-green-500/10
- Primary accent: text-primary (teal)
- Muted text: text-muted-foreground
- Card bg: bg-card
- Border: border-border/50

## API Namespaces Available
dashboardApi, nerveCenterApi, findingsApi, scannerApi, appsApi, failApi, changesApi, mpteApi, 
remediationApi, evidenceApi, complianceApi, copilotApi, integrationsApi, reportsApi, teamsApi, 
usersApi, workflowsApi, auditApi, policiesApi, systemApi, knowledgeGraphApi, threatFeedsApi, 
predictionsApi, playbooks
