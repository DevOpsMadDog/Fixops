/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Defense coverage summary for an org.
 */
export type DefenseCoverage = {
    org_id: string;
    total_simulations: number;
    scenarios_tested: Array<string>;
    scenarios_not_tested: Array<string>;
    average_score: number;
    weakest_scenario: (string | null);
    strongest_scenario: (string | null);
    coverage_percent: number;
};

