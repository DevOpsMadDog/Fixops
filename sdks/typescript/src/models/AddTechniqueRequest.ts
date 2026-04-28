/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddTechniqueRequest = {
    /**
     * e.g. T1190
     */
    technique_id: string;
    name: string;
    /**
     * e.g. TA0001
     */
    tactic_id: string;
    description?: string;
    /**
     * critical|high|medium|low
     */
    severity?: string;
};

