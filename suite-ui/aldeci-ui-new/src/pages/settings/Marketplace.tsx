import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { Store, Download } from "lucide-react";

export default function Marketplace() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Marketplace" description="Extensions, plugins, and scanner integrations" />
      <Card><CardContent className="pt-6"><EmptyState icon={Store} title="Marketplace" description="Browse and install scanner plugins, integrations, and extensions. Coming soon for enterprise deployments." action={<Button variant="outline" size="sm" disabled><Download className="mr-2 h-4 w-4" />Browse Extensions</Button>} /></CardContent></Card>
    </div>
  );
}
