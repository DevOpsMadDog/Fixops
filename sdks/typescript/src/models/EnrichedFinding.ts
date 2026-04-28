/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A raw scanner finding enriched with CVE intel, EPSS, KEV, and risk score.
 */
export type EnrichedFinding = {
    /**
     * The raw finding dict as received from the scanner
     */
    original_finding: Record<string, any>;
    /**
     * CVE IDs matched via CWE mapping or scanner output
     */
    matched_cves?: Array<string>;
    /**
     * EPSS probability per CVE (0.0–1.0)
     */
    epss_scores?: Record<string, number>;
    /**
     * True if any matched CVE is in CISA KEV
     */
    in_kev?: boolean;
    /**
     * CISA KEV remediation due date (ISO-8601) for the highest-priority KEV CVE
     */
    kev_due_date?: (string | null);
    /**
     * Human-readable remediation guidance from NVD references
     */
    fix_guidance?: string;
    /**
     * Composite risk 0–100: (CVSS/10*40) + (EPSS*35) + (in_kev*25)
     */
    composite_risk_score?: number;
    /**
     * ISO-8601 timestamp when enrichment was performed
     */
    enriched_at?: string;
};

