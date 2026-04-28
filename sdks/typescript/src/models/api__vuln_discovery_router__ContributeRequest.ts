/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ContributionProgram } from './ContributionProgram';
/**
 * Request to submit vulnerability to CVE program.
 */
export type api__vuln_discovery_router__ContributeRequest = {
    /**
     * ALdeci internal vulnerability ID
     */
    vuln_id: string;
    program: ContributionProgram;
    researcher_name: string;
    researcher_email: string;
    organization?: (string | null);
    /**
     * Proposed disclosure timeline (e.g., '90 days')
     */
    disclosure_timeline?: (string | null);
    coordinate_with_vendor?: boolean;
    vendor_contact?: (string | null);
    additional_references?: Array<string>;
};

