/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__license_compliance__PolicyRule } from './core__license_compliance__PolicyRule';
/**
 * A full policy configuration for a project.
 */
export type LicensePolicy = {
    policy_id: string;
    name: string;
    description?: string;
    rules?: Array<core__license_compliance__PolicyRule>;
    /**
     * Max % of dependencies that may be copyleft
     */
    max_copyleft_percentage?: number;
    require_osi_approved?: boolean;
    project_license?: (string | null);
};

