import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary/15 text-primary",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive: "border-transparent bg-destructive/15 text-destructive",
        outline: "text-foreground",
        success: "border-transparent bg-green-500/15 text-green-400",
        warning: "border-transparent bg-yellow-500/15 text-yellow-400",
        critical: "border-transparent bg-red-500/15 text-red-400",
        high: "border-transparent bg-orange-500/15 text-orange-400",
        medium: "border-transparent bg-yellow-500/15 text-yellow-400",
        low: "border-transparent bg-blue-500/15 text-blue-400",
        info: "border-transparent bg-cyan-500/15 text-cyan-400",
        new: "border-transparent bg-purple-500/15 text-purple-400",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
