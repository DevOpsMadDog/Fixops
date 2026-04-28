/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SetGeoRedundancyRequest = {
    /**
     * System this geo record covers
     */
    system_name: string;
    /**
     * Primary datacenter / cloud region
     */
    primary_location: string;
    backup_locations?: Array<string>;
    distance_km?: (number | null);
    data_residency_region?: string;
    residency_compliant?: boolean;
    required_residency?: (string | null);
    compliance_frameworks?: Array<string>;
    notes?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: string;
};

