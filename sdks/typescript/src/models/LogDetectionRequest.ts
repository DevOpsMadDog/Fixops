/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type LogDetectionRequest = {
    technique_id: string;
    /**
     * e.g. 'ids', 'siem', 'edr'
     */
    source: string;
    confidence?: number;
    metadata?: (Record<string, any> | null);
};

