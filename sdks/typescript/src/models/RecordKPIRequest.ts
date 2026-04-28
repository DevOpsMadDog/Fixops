/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordKPIRequest = {
    /**
     * One of: ['mttd_hours', 'mttr_hours', 'mttr_critical_hours', 'patch_compliance_pct', 'vuln_density', 'sla_compliance_pct', 'false_positive_rate', 'open_critical_count', 'incidents_per_month', 'posture_score']
     */
    kpi_name: string;
    /**
     * Numeric KPI value
     */
    value: number;
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * 'daily'|'weekly'|'monthly'
     */
    period?: (string | null);
    metadata?: (Record<string, any> | null);
};

