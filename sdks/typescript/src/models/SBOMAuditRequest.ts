/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SBOMComponent } from './SBOMComponent';
/**
 * Request body for SBOM compliance audit.
 */
export type SBOMAuditRequest = {
    components: Array<SBOMComponent>;
    /**
     * Policy to apply
     */
    policy_id?: string;
    /**
     * Optional report ID
     */
    report_id?: (string | null);
};

