/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__agents_router__ComplianceFramework } from './api__agents_router__ComplianceFramework';
/**
 * Request for audit evidence collection.
 */
export type AuditEvidenceRequest = {
    framework: api__agents_router__ComplianceFramework;
    controls?: Array<string>;
    format?: string;
};

