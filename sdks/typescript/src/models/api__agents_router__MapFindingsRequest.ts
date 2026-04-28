/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__agents_router__ComplianceFramework } from './api__agents_router__ComplianceFramework';
/**
 * Request to map findings to compliance frameworks.
 */
export type api__agents_router__MapFindingsRequest = {
    finding_ids: Array<string>;
    frameworks: Array<api__agents_router__ComplianceFramework>;
};

