/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for an audit log.
 */
export type apps__api__audit_router__AuditLogResponse = {
    id: string;
    event_type: string;
    severity: string;
    user_id: (string | null);
    resource_type: (string | null);
    resource_id: (string | null);
    action: string;
    details: Record<string, any>;
    ip_address: (string | null);
    user_agent: (string | null);
    timestamp: string;
};

