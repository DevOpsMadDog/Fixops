/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { VerificationModuleResult } from './VerificationModuleResult';
export type VerificationReportResponse = {
    org_id: string;
    modules: Array<VerificationModuleResult>;
    verified_at: string;
    all_match: boolean;
};

