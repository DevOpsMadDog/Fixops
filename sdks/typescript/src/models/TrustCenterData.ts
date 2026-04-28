/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ComplianceBadge } from './ComplianceBadge';
import type { SecurityControl } from './SecurityControl';
import type { SubprocessorEntry } from './SubprocessorEntry';
import type { TrustPageConfig } from './TrustPageConfig';
/**
 * Aggregated public trust center page data — NO SECRETS.
 */
export type TrustCenterData = {
    config: TrustPageConfig;
    badges?: Array<ComplianceBadge>;
    controls?: Array<SecurityControl>;
    subprocessors?: Array<SubprocessorEntry>;
    last_updated?: string;
};

