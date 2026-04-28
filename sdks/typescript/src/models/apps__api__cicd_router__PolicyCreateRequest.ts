/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__cicd_integration__PolicyRule } from './core__cicd_integration__PolicyRule';
/**
 * Create a new CI/CD policy.
 */
export type apps__api__cicd_router__PolicyCreateRequest = {
    /**
     * Organisation ID (optional)
     */
    org_id?: string;
    /**
     * Policy rules
     */
    rules: Array<core__cicd_integration__PolicyRule>;
};

