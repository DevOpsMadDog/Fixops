/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_indicator_router__IndicatorCreate = {
    indicator_value: string;
    indicator_type: string;
    source?: string;
    confidence?: number;
    severity?: string;
    tlp?: string;
    tags?: Array<string>;
    expiry_at?: (string | null);
};

