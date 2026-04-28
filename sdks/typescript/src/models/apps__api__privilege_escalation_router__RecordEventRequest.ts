/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__privilege_escalation_router__RecordEventRequest = {
    /**
     * Organization identifier
     */
    org_id: string;
    /**
     * User or service account identifier
     */
    user_id: string;
    /**
     * Role/permission level before escalation
     */
    from_role: string;
    /**
     * Role/permission level after escalation
     */
    to_role: string;
    /**
     * Escalation method: sudo/setuid/token/exploit/impersonation/suid/other
     */
    method?: string;
    /**
     * Source IP address of the escalation event
     */
    source_ip?: string;
};

