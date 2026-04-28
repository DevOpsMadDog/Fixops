/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Gap analysis across all simulations for an org.
 */
export type GapAnalysis = {
    org_id: string;
    total_simulations: number;
    recurring_gaps: Array<string>;
    gap_frequency: Record<string, number>;
    critical_gaps: Array<string>;
    recommended_priorities: Array<string>;
};

