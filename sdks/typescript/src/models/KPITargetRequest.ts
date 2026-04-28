/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for configuring KPI thresholds.
 */
export type KPITargetRequest = {
    /**
     * KPI name
     */
    name: string;
    /**
     * Ideal target value
     */
    target: number;
    /**
     * Yellow alert threshold
     */
    yellow: number;
    /**
     * Red alert threshold
     */
    red: number;
    /**
     * True for coverage/rate KPIs; False for MTTD/MTTR
     */
    higher_is_better?: boolean;
};

