/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ScanStatus } from './ScanStatus';
/**
 * Result of a full attack surface scan.
 */
export type core__attack_surface_manager__ScanResult = {
    id?: string;
    org_id?: string;
    status?: ScanStatus;
    started_at?: (string | null);
    completed_at?: (string | null);
    assets_discovered?: number;
    shadow_it_count?: number;
    critical_count?: number;
    high_count?: number;
    changes_detected?: number;
    overall_score?: number;
    error?: (string | null);
};

