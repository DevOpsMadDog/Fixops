/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__supply_chain_security__RiskLevel } from './core__supply_chain_security__RiskLevel';
import type { core__supply_chain_security__VendorTier } from './core__supply_chain_security__VendorTier';
/**
 * Security risk assessment for a software vendor.
 */
export type VendorRiskAssessment = {
    id?: string;
    vendor_name: string;
    vendor_url?: (string | null);
    tier?: core__supply_chain_security__VendorTier;
    org_id?: string;
    security_score?: number;
    /**
     * Reported uptime %
     */
    sla_uptime_pct?: (number | null);
    /**
     * Incident response SLA hours
     */
    sla_response_hours?: (number | null);
    sla_compliant?: boolean;
    /**
     * Number of publicly known breaches
     */
    known_breaches?: number;
    last_breach_date?: (string | null);
    breach_details?: Array<string>;
    /**
     * Number of components sourced from this vendor
     */
    component_count?: number;
    concentration_risk?: core__supply_chain_security__RiskLevel;
    security_contact?: (string | null);
    bug_bounty?: boolean;
    mfa_required?: boolean;
    sbom_provided?: boolean;
    notes?: string;
    created_at?: string;
    updated_at?: string;
};

