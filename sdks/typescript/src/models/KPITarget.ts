/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Threshold configuration for a KPI.
 */
export type KPITarget = {
    /**
     * KPI name this target applies to
     */
    kpi_name: string;
    /**
     * Ideal / goal value
     */
    target_value: number;
    /**
     * Value at which KPI turns yellow
     */
    threshold_yellow: number;
    /**
     * Value at which KPI turns red
     */
    threshold_red: number;
    /**
     * True = higher values are better (e.g. coverage). False = lower values are better (e.g. MTTD).
     */
    higher_is_better?: boolean;
};

