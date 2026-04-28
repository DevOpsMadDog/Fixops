/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__supply_chain_security__VendorTier } from './core__supply_chain_security__VendorTier';
/**
 * Request body for creating or updating a vendor risk assessment.
 */
export type CreateVendorRequest = {
    /**
     * Vendor / publisher name
     */
    vendor_name: string;
    vendor_url?: (string | null);
    tier?: core__supply_chain_security__VendorTier;
    org_id?: string;
    security_score?: number;
    sla_uptime_pct?: (number | null);
    sla_response_hours?: (number | null);
    sla_compliant?: boolean;
    known_breaches?: number;
    breach_details?: Array<string>;
    component_count?: number;
    security_contact?: (string | null);
    bug_bounty?: boolean;
    mfa_required?: boolean;
    sbom_provided?: boolean;
    notes?: string;
};

