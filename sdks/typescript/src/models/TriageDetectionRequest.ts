/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TriageDetectionRequest = {
    /**
     * new | triaged | investigating | escalated | resolved | false_positive
     */
    new_status: string;
    auto_triaged?: boolean;
    triage_time_seconds?: number;
};

