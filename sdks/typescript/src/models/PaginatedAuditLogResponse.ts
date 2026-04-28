/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__audit_router__AuditLogResponse } from './apps__api__audit_router__AuditLogResponse';
/**
 * Paginated audit log response.
 */
export type PaginatedAuditLogResponse = {
    items: Array<apps__api__audit_router__AuditLogResponse>;
    total: number;
    limit: number;
    offset: number;
};

