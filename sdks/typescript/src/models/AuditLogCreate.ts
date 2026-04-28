/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AuditEventType } from './AuditEventType';
import type { AuditSeverity } from './AuditSeverity';
/**
 * Request model for creating an audit log.
 */
export type AuditLogCreate = {
    event_type: AuditEventType;
    severity?: AuditSeverity;
    user_id?: (string | null);
    resource_type?: (string | null);
    resource_id?: (string | null);
    action: string;
    details?: Record<string, any>;
    ip_address?: (string | null);
    user_agent?: (string | null);
};

