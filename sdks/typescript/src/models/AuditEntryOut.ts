/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Serialisable audit entry.
 */
export type AuditEntryOut = {
    id: string;
    org_id: string;
    timestamp: string;
    source_format: string;
    severity: string;
    actor: string;
    actor_ip: string;
    action: string;
    resource_type: string;
    resource_id: string;
    outcome: string;
    status: string;
    checksum: string;
    details?: Record<string, any>;
};

