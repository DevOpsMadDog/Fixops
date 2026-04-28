/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DriftCreate = {
    /**
     * Cloud resource identifier
     */
    resource_id: string;
    /**
     * config_changed / resource_deleted / new_resource / tag_missing / permission_widened
     */
    drift_type?: string;
    /**
     * critical / high / medium / low
     */
    severity?: string;
    /**
     * Expected configuration value
     */
    expected_value?: string;
    /**
     * Actual observed configuration value
     */
    actual_value?: string;
    /**
     * ISO 8601 detection timestamp
     */
    detected_at?: (string | null);
};

