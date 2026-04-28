/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__license_compliance__PolicyAction } from './core__license_compliance__PolicyAction';
import type { LicenseCategory } from './LicenseCategory';
/**
 * A single configurable policy rule.
 */
export type core__license_compliance__PolicyRule = {
    rule_id: string;
    description: string;
    action: core__license_compliance__PolicyAction;
    categories?: Array<LicenseCategory>;
    /**
     * Specific SPDX IDs
     */
    license_ids?: Array<string>;
    enabled?: boolean;
};

