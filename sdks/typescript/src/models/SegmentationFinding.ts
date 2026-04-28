/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__network_security__Severity } from './core__network_security__Severity';
import type { SegmentationStatus } from './SegmentationStatus';
export type SegmentationFinding = {
    id?: string;
    org_id: string;
    segment_name: string;
    compliance_framework: string;
    status: SegmentationStatus;
    severity: core__network_security__Severity;
    description: string;
    affected_assets?: Array<string>;
    recommendation: string;
    detected_at?: string;
};

