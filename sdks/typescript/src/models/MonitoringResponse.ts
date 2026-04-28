/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Continuous monitoring data for a vendor.
 */
export type MonitoringResponse = {
    vendor_id: string;
    total_signals: number;
    active_signals: number;
    severity_breakdown: Record<string, number>;
    latest_security_rating: (Record<string, any> | null);
    signals: Array<Record<string, any>>;
};

