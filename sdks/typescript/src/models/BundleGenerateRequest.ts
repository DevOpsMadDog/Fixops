/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DateRangeModel } from './DateRangeModel';
/**
 * Request body for POST /evidence/bundles/generate.
 *
 * The UI sends ``frameworks`` (list), ``date_range`` (object with start/end),
 * and ``categories`` (list of evidence category identifiers).
 */
export type BundleGenerateRequest = {
    /**
     * Compliance frameworks to include
     */
    frameworks?: (Array<string> | null);
    /**
     * (deprecated) Single framework; use 'frameworks' list instead
     */
    framework?: (string | null);
    /**
     * Date range for evidence collection
     */
    date_range?: (DateRangeModel | null);
    /**
     * Evidence categories to include
     */
    categories?: Array<string>;
};

