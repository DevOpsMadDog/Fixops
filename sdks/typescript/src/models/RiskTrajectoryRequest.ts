/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for risk trajectory calculation.
 */
export type RiskTrajectoryRequest = {
    /**
     * Current security state
     */
    current_state?: string;
    /**
     * Number of steps to predict
     */
    horizon_steps?: number;
};

