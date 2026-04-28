/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__supply_chain_security__RiskLevel } from './core__supply_chain_security__RiskLevel';
import type { LicenseRisk } from './LicenseRisk';
/**
 * Risk score for a single dependency.
 */
export type DependencyRiskScore = {
    component_id: string;
    component_name: string;
    component_version: string;
    /**
     * 0=safe, 100=critical
     */
    overall_score?: number;
    risk_level?: core__supply_chain_security__RiskLevel;
    /**
     * Known CVE count
     */
    cve_count?: number;
    critical_cve_count?: number;
    days_since_last_commit?: (number | null);
    open_issues_count?: (number | null);
    license_risk?: LicenseRisk;
    transitive_depth?: number;
    weekly_downloads?: (number | null);
    is_maintained?: boolean;
    score_breakdown?: Record<string, number>;
    computed_at?: string;
};

