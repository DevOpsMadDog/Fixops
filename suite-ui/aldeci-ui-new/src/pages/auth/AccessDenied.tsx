import { Shield, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";

export default function AccessDenied() {
  const navigate = useNavigate();
  const { user } = useAuth();

  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
        <Shield className="h-8 w-8 text-destructive" />
      </div>
      <h2 className="text-xl font-semibold">Access Denied</h2>
      <p className="max-w-md text-sm text-muted-foreground">
        Your role <span className="font-medium text-foreground">({user?.role ?? "unknown"})</span> does
        not have permission to view this page. Contact your administrator for access.
      </p>
      <Button variant="outline" onClick={() => navigate(-1)}>
        <ArrowLeft className="mr-2 h-4 w-4" />
        Go back
      </Button>
    </div>
  );
}
