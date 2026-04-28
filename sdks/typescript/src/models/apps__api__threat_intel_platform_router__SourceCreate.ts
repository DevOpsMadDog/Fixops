/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_intel_platform_router__SourceCreate = {
    source_name: string;
    source_type?: string;
    feed_url?: string;
    api_key_masked?: string;
    status?: string;
    reliability_score?: number;
    update_frequency_hours?: number;
    last_updated?: (string | null);
    total_indicators?: number;
};

