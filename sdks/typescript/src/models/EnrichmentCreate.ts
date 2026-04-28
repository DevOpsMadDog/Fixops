/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EnrichmentCreate = {
    ioc_value: string;
    ioc_type?: string;
    sources?: Array<string>;
    confidence_score?: number;
    threat_categories?: Array<string>;
    is_malicious?: boolean;
    first_seen?: (string | null);
    last_seen?: (string | null);
};

