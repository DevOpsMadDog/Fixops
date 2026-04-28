/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntSeverity } from './HuntSeverity';
/**
 * A Sigma detection rule.
 */
export type SigmaRule = {
    id?: string;
    name: string;
    description?: string;
    author?: string;
    status?: string;
    logsource_category?: string;
    logsource_product?: string;
    detection_keywords?: Array<string>;
    detection_condition?: string;
    false_positives?: Array<string>;
    level?: HuntSeverity;
    tags?: Array<string>;
    raw_yaml?: string;
    search_query?: string;
    created_at?: string;
    enabled?: boolean;
};

