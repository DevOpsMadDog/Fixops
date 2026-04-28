/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EscalationPolicyRequest = {
    /**
     * Hours past SLA deadline before auto-escalation fires
     */
    breach_threshold_hours?: number;
    /**
     * Default escalation action
     */
    auto_action?: string;
    /**
     * Whether to bump severity on escalation
     */
    severity_bump?: boolean;
};

