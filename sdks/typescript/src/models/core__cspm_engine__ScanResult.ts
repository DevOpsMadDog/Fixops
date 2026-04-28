/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { OrgPosture } from './OrgPosture';
export type core__cspm_engine__ScanResult = {
    scan_id?: string;
    org_id?: string;
    resources_scanned?: number;
    findings_count?: number;
    drift_events_count?: number;
    posture?: (OrgPosture | null);
    started_at?: string;
    completed_at?: string;
};

