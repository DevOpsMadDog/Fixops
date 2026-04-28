/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__pipeline_router__FindingInput } from './api__pipeline_router__FindingInput';
import type { AssetInput } from './AssetInput';
export type EvidenceGenerateRequest = {
    org_id?: string;
    timeframe_days?: number;
    controls?: (Array<string> | null);
    pipeline_run_id?: (string | null);
    findings?: Array<api__pipeline_router__FindingInput>;
    assets?: Array<AssetInput>;
};

