/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_correlation_router__SignalIngest = {
    signal_type?: string;
    source_engine?: string;
    signal_id?: string;
    entity_type?: string;
    entity_value: string;
    severity?: string;
    description?: string;
    timestamp?: (string | null);
    ttl_minutes?: number;
};

