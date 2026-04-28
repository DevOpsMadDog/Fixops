/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PatchPriority } from './PatchPriority';
import type { PatchStatus } from './PatchStatus';
export type Patch = {
    id?: string;
    /**
     * Associated CVE identifier, e.g. CVE-2024-1234
     */
    cve_id?: (string | null);
    /**
     * Package or component name
     */
    package_name: string;
    /**
     * Currently installed version
     */
    current_version: string;
    /**
     * Version that resolves the vulnerability
     */
    fixed_version: string;
    /**
     * Patch urgency
     */
    priority?: PatchPriority;
    /**
     * Current lifecycle state
     */
    status?: PatchStatus;
    /**
     * Asset IDs impacted by this patch
     */
    affected_assets?: Array<string>;
    /**
     * ISO-8601 date/time scheduled for deployment
     */
    scheduled_date?: (string | null);
    /**
     * ISO-8601 date/time actually deployed
     */
    deployed_date?: (string | null);
    /**
     * When the patch was first discovered
     */
    discovered_date?: string;
    /**
     * Organisation the patch belongs to
     */
    org_id?: string;
    /**
     * Free-form notes or change-ticket reference
     */
    notes?: (string | null);
};

