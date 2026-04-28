/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CompleteExecutionBody = {
    /**
     * finding | no_finding | partial_finding | inconclusive
     */
    outcome: string;
    /**
     * Number of findings discovered
     */
    findings_count?: number;
    /**
     * IOCs discovered during hunt
     */
    iocs_discovered?: (Array<string> | null);
    /**
     * Hunt notes and observations
     */
    notes?: string;
};

