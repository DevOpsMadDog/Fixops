/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ForwardEventRequest = {
    /**
     * Event type identifier
     */
    event_type: string;
    /**
     * critical, high, medium, low, info
     */
    severity?: string;
    /**
     * Action taken
     */
    action?: string;
    /**
     * Outcome of the action
     */
    outcome?: string;
    /**
     * Human-readable message
     */
    message?: string;
    src_ip?: string;
    dst_ip?: string;
    user_id?: string;
    app_id?: string;
    finding_id?: string;
    cve_id?: string;
    metadata?: Record<string, any>;
};

