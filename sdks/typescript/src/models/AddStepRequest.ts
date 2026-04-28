/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddStepRequest = {
    org_id?: string;
    /**
     * MITRE technique ID e.g. T1059
     */
    technique_id?: string;
    /**
     * Technique name
     */
    technique_name: string;
    /**
     * ATT&CK tactic
     */
    tactic: string;
    /**
     * Asset targeted in this step
     */
    asset_targeted?: string;
    /**
     * success/failed/unknown
     */
    outcome?: string;
    /**
     * Step number (auto if omitted)
     */
    step_number?: (number | null);
    /**
     * Evidence items
     */
    evidence?: Array<string>;
};

