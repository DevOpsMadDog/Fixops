/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PatchPriority } from './PatchPriority';
export type AddPatchRequest = {
    /**
     * CVE identifier, e.g. CVE-2024-1234
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
     * Asset IDs affected
     */
    affected_assets?: Array<string>;
    /**
     * Change ticket or free-form notes
     */
    notes?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: string;
};

