/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type LogEmailEventRequest = {
    sender: string;
    recipient: string;
    subject?: string;
    filter_result: string;
    rule_id?: string;
    threat_score?: number;
    processed_at?: (string | null);
};

