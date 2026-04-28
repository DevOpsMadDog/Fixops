/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EnrichmentResultCreate = {
    source: string;
    reputation_score?: number;
    malicious?: boolean;
    tags?: Array<string>;
    context?: string;
    confidence?: number;
    first_seen?: (string | null);
    last_seen?: (string | null);
};

