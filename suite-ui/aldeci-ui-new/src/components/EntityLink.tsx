import { Link } from "react-router-dom";
import { entityLink } from "@/lib/entity-links";

interface EntityLinkProps {
  type: string;
  id: string;
  children: React.ReactNode;
  className?: string;
}

export function EntityLink({ type, id, children, className }: EntityLinkProps) {
  return (
    <Link
      to={entityLink(type, id)}
      className={className ?? "text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors"}
    >
      {children}
    </Link>
  );
}
