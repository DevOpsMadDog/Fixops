// Maps entity types to their detail pages
const ENTITY_ROUTES: Record<string, (id: string) => string> = {
  alert:     (id) => `/alert-triage?alert=${id}`,
  incident:  (id) => `/incident-response?id=${id}`,
  cve:       (id) => `/vuln-intelligence?cve=${id}`,
  asset:     (id) => `/asset-inventory?id=${id}`,
  finding:   (id) => `/security-findings?id=${id}`,
  component: (id) => `/supply-chain-dashboard?component=${id}`,
  actor:     (id) => `/threat-intel?actor=${id}`,
  control:   (id) => `/compliance?control=${id}`,
  risk:      (id) => `/risk-register?risk=${id}`,
  policy:    (id) => `/compliance?policy=${id}`,
};

export function entityLink(type: string, id: string): string {
  return ENTITY_ROUTES[type]?.(id) ?? `/brain/nodes/${id}`;
}
