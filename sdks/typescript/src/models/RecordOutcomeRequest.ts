/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordOutcomeRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * cost-avoidance|incident-reduction|efficiency|compliance|risk-reduction|revenue-protection
     */
    outcome_type: string;
    /**
     * Outcome description
     */
    description?: string;
    /**
     * Quantified monetary value
     */
    quantified_value?: number;
    /**
     * ISO measurement date
     */
    measurement_date?: string;
    /**
     * Whether outcome is verified
     */
    verified?: boolean;
};

