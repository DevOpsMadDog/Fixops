/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * RPO/RTO targets and actuals for a logical system.
 */
export type RPOConfig = {
    id?: string;
    system_name: string;
    /**
     * Recovery Point Objective target in minutes
     */
    rpo_target_minutes?: number;
    /**
     * Recovery Time Objective target in minutes
     */
    rto_target_minutes?: number;
    /**
     * Measured RPO from last backup interval
     */
    rpo_actual_minutes?: (number | null);
    /**
     * Measured RTO from last restore test
     */
    rto_actual_minutes?: (number | null);
    rpo_compliant?: boolean;
    rto_compliant?: boolean;
    last_evaluated_at?: (string | null);
    notes?: (string | null);
    org_id?: string;
    created_at?: string;
    updated_at?: string;
};

