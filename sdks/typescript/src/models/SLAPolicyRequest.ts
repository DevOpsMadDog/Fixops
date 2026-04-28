/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Payload for creating or updating an SLA policy.
 */
export type SLAPolicyRequest = {
    name: string;
    severity_deadlines?: Record<string, number>;
    escalation_chain?: Array<string>;
    grace_period_hours?: number;
    enabled?: boolean;
};

