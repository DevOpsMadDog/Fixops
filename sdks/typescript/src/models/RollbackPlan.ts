/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Rollback plan for a change request.
 */
export type RollbackPlan = {
    /**
     * Ordered rollback steps
     */
    steps: Array<string>;
    /**
     * Criteria to confirm rollback success
     */
    validation_criteria?: Array<string>;
    /**
     * Maximum time allowed for rollback in minutes
     */
    max_rollback_time_minutes?: number;
    /**
     * Person responsible for executing rollback
     */
    responsible_person: string;
    /**
     * Whether rollback can be automated
     */
    automated?: boolean;
    /**
     * Script to execute for automated rollback
     */
    rollback_script?: (string | null);
};

