/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__incident_timeline_router__EventCreate = {
    event_time?: (string | null);
    event_type?: string;
    title: string;
    description?: string;
    actor?: string;
    source_system?: string;
    evidence_refs?: Array<any>;
    severity?: string;
};

