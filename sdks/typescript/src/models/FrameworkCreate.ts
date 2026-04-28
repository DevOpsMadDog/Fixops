/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FrameworkCreate = {
    /**
     * Framework name, e.g. SOC2, ISO27001
     */
    name: string;
    /**
     * Framework version
     */
    version?: string;
    total_controls?: number;
    implemented_controls?: number;
    compliance_score?: number;
    last_assessed?: (string | null);
};

