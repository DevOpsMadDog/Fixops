/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__risk_quantification_engine_router__ControlCreate = {
    /**
     * Control name
     */
    control_name: string;
    /**
     * preventive/detective/corrective/deterrent/recovery
     */
    control_type?: string;
    /**
     * One-time implementation cost $
     */
    implementation_cost?: number;
    /**
     * Annual recurring cost $
     */
    annual_cost?: number;
    /**
     * Effectiveness percentage 0-100
     */
    effectiveness_pct?: number;
};

