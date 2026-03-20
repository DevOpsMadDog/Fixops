import { type ReactNode, isValidElement } from "react";
import { cn, formatNumber } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { type LucideIcon } from "lucide-react";
import { motion } from "framer-motion";

export interface KpiCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  description?: string;
  icon?: LucideIcon | ReactNode;
  trend?: "up" | "down" | "flat";
  trendLabel?: string;
  className?: string;
  onClick?: () => void;
}

export function KpiCard({
  title,
  value,
  change,
  changeLabel,
  description,
  icon: Icon,
  trend,
  trendLabel,
  className,
  onClick,
}: KpiCardProps) {
  const trendColor =
    trend === "up"
      ? "text-green-400"
      : trend === "down"
        ? "text-red-400"
        : "text-muted-foreground";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Card className={cn("p-5", onClick && "cursor-pointer hover:border-primary/30 transition-colors", className)} onClick={onClick} role={onClick ? "button" : undefined} tabIndex={onClick ? 0 : undefined} onKeyDown={onClick ? (e) => e.key === "Enter" && onClick() : undefined}>
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {title}
            </p>
            <p className="text-2xl font-bold tabular-nums tracking-tight">
              {typeof value === "number" ? formatNumber(value) : value}
            </p>
            {change !== undefined && (
              <p className={cn("text-xs font-medium", trendColor)}>
                {change > 0 ? "+" : ""}
                {change}% {changeLabel ?? ""}
              </p>
            )}
            {!change && trendLabel && (
              <p className={cn("text-xs font-medium", trendColor)}>
                {trendLabel}
              </p>
            )}
            {description && !trendLabel && (
              <p className="text-xs text-muted-foreground">{description}</p>
            )}
          </div>
          {Icon && (
            <div className="rounded-lg bg-primary/10 p-2.5">
              {isValidElement(Icon) ? (
                Icon
              ) : typeof Icon === "function" ? (
                <Icon className="h-5 w-5 text-primary" />
              ) : null}
            </div>
          )}
        </div>
      </Card>
    </motion.div>
  );
}
