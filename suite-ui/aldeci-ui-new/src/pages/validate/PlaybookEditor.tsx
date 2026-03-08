import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { FileEdit, Plus } from "lucide-react";

export default function PlaybookEditor() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Playbook Editor" description="Create and edit security response playbooks"
        actions={<Button size="sm"><Plus className="mr-2 h-4 w-4" />New Playbook</Button>} />
      <Card><CardContent className="pt-6"><EmptyState icon={FileEdit} title="Playbook Editor" description="Select a playbook to edit or create a new one. Playbooks define automated response workflows for security incidents." /></CardContent></Card>
    </div>
  );
}
