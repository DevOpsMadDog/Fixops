/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__pipeline_router__FindingInput } from './api__pipeline_router__FindingInput';
import type { AssetInput } from './AssetInput';
export type PipelineRunRequest = {
    org_id?: string;
    findings?: Array<api__pipeline_router__FindingInput>;
    assets?: Array<AssetInput>;
    source?: string;
    run_pentest?: boolean;
    run_playbooks?: boolean;
    generate_evidence?: boolean;
    evidence_framework?: string;
    evidence_timeframe_days?: number;
    policy_rules?: null;
};

