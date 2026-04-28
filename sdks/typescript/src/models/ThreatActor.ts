/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Known threat actor (APT group, criminal org, nation-state).
 *
 * Attributes:
 * id: Unique actor identifier (e.g. "apt29")
 * name: Common name (e.g. "Cozy Bear")
 * aliases: Known alternate names
 * ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
 * motivation: Primary motivation (espionage, financial, etc.)
 * origin_country: Attributed country of origin
 * active: Whether actor is currently active
 * associated_campaigns: Campaign IDs linked to this actor
 * iocs: Indicators of Compromise (IPs, domains, hashes, etc.)
 */
export type ThreatActor = {
    id?: string;
    name: string;
    aliases?: Array<string>;
    ttps?: Array<string>;
    motivation?: string;
    origin_country?: (string | null);
    active?: boolean;
    associated_campaigns?: Array<string>;
    iocs?: Array<string>;
};

