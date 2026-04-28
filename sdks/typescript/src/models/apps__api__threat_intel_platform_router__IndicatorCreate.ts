/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_intel_platform_router__IndicatorCreate = {
    indicator_type: string;
    value: string;
    source_id?: string;
    severity?: string;
    confidence?: number;
    threat_category?: string;
    tags?: Array<string>;
    first_seen?: (string | null);
    last_seen?: (string | null);
    expiry_date?: (string | null);
    tlp_level?: string;
    hit_count?: number;
    mitre_techniques?: Array<string>;
};

