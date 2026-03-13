import { useNavigate } from "react-router-dom";
import { LayoutDashboard } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col items-center justify-center py-24 px-8 text-center w-full">
      {/* Large 404 */}
      <p className="font-mono text-7xl sm:text-8xl font-bold leading-none text-border select-none">
        404
      </p>

      {/* Heading */}
      <h1 className="mt-4 text-xl sm:text-2xl font-semibold text-foreground">
        Page not found
      </h1>

      {/* Sub-copy */}
      <p className="mt-2 text-sm text-muted-foreground max-w-md leading-relaxed">
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
