/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AuditEntryOut } from './AuditEntryOut';
/**
 * Paginated search response.
 */
export type apps__api__audit_analytics_router__SearchResponse = {
    items: Array<AuditEntryOut>;
    total: number;
    limit: number;
    offset: number;
    query: string;
};

