/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DataResidencyRegion } from './DataResidencyRegion';
/**
 * Geographic backup location tracking for data residency compliance.
 */
export type GeoRedundancyRecord = {
    id?: string;
    system_name: string;
    primary_location: string;
    backup_locations?: Array<string>;
    /**
     * Distance from primary to nearest backup (km)
     */
    distance_km?: (number | null);
    data_residency_region?: DataResidencyRegion;
    residency_compliant?: boolean;
    required_residency?: (string | null);
    compliance_frameworks?: Array<string>;
    last_verified_at?: (string | null);
    notes?: (string | null);
    org_id?: string;
    created_at?: string;
    updated_at?: string;
};

