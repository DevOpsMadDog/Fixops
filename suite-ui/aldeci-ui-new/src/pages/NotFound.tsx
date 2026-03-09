import { useNavigate } from "react-router-dom";
import { LayoutDashboard } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '6rem 2rem', textAlign: 'center', width: '100%' }}>
      {/* Large 404 */}
      <p style={{ fontFamily: 'monospace', fontSize: '8rem', fontWeight: 'bold', lineHeight: 1, color: 'var(--border)', userSelect: 'none' }}>
        404
      </p>

      {/* Heading */}
      <h1 style={{ marginTop: '1rem', fontSize: '1.5rem', fontWeight: 600, color: 'var(--foreground)' }}>
        Page not found
      </h1>

      {/* Sub-copy */}
      <p style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: 'var(--muted-foreground)', maxWidth: '28rem', lineHeight: 1.6 }}>
        The resource you requested does not exist or you do not have permission to access it. Verify the URL or return to the command dashboard.
      </p>

      {/* CTA */}
      <Button
        className="mt-8"
        size="lg"
        onClick={() => navigate("/", { replace: true })}
      >
        <LayoutDashboard className="h-4 w-4" />
        Return to Command Dashboard
      </Button>
    </div>
  );
}
