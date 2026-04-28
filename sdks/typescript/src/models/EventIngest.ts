/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__security_metrics__Severity } from './core__security_metrics__Severity';
/**
 * Request body for ingesting a security event.
 */
export type EventIngest = {
    severity?: core__security_metrics__Severity;
    detected_at?: (string | null);
    contained_at?: (string | null);
    remediated_at?: (string | null);
    source?: string;
    team?: string;
    repo?: string;
    tags?: Array<string>;
    is_regression?: boolean;
};

