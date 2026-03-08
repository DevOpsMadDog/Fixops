import { useNavigate } from "react-router-dom";
import { LayoutDashboard } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-6 text-center">
      {/* Large 404 */}
      <p className="select-none font-mono text-[8rem] font-bold leading-none text-border sm:text-[10rem]">
        404
      </p>

      {/* Heading */}
      <h1 className="mt-4 text-2xl font-semibold text-foreground">
        Page not found
      </h1>

      {/* Sub-copy */}
      <p className="mt-2 max-w-sm text-sm text-muted-foreground">
        The resource you requested does not exist or you do not have permission
        to access it. Verify the URL or return to the command dashboard.
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
