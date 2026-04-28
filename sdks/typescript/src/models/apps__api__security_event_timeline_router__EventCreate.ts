/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_event_timeline_router__EventCreate = {
    incident_id: string;
    event_time: string;
    event_type: string;
    source_system: string;
    actor?: string;
    target?: string;
    action: string;
    outcome?: string;
    severity?: string;
    raw_data?: string;
    tags?: Array<string>;
};

