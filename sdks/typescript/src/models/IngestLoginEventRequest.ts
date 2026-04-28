/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IngestLoginEventRequest = {
    event_type?: string;
    src_ip?: string;
    geo_country?: string;
    device_id?: string;
    success?: boolean;
    risk_indicators?: Array<string>;
    observed_at?: (string | null);
};

