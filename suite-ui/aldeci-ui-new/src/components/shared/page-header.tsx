import { type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { type LucideIcon } from "lucide-react";

interface PageHeaderProps {
  title: string;
  description?: string;
  badge?: string;
  icon?: LucideIcon | ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}

export function PageHeader({ title, description, badge, icon: _icon, actions, children, className }: PageHeaderProps) {
  const actionContent = actions || children;
  return (
    <div className={cn("flex items-start justify-between gap-6", className)}>
      <div className="space-y-1.5 min-w-0 flex-1">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
          {badge && <Badge variant="new">{badge}</Badge>}
        </div>
        {description && (
          <p className="text-sm text-muted-foreground leading-relaxed">{description}</p>
        )}
      </div>
      {actionContent && <div className="flex items-center gap-2 shrink-0">{actionContent}</div>}
    </div>
  );
}
