/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Full FAIR model simulation request.
 */
export type FAIRSimulationRequest = {
    /**
     * Min threat event frequency (per year)
     */
    tef_min?: number;
    /**
     * Max threat event frequency
     */
    tef_max?: number;
    /**
     * Most likely threat event frequency
     */
    tef_mode?: number;
    /**
     * Min vulnerability probability
     */
    vuln_min?: number;
    /**
     * Max vulnerability probability
     */
    vuln_max?: number;
    /**
     * Most likely vulnerability probability
     */
    vuln_mode?: number;
    /**
     * Min primary loss ($)
     */
    primary_loss_min?: number;
    /**
     * Max primary loss ($)
     */
    primary_loss_max?: number;
    /**
     * Most likely primary loss ($)
     */
    primary_loss_mode?: number;
    /**
     * Min secondary loss ($)
     */
    secondary_loss_min?: number;
    /**
     * Max secondary loss ($)
     */
    secondary_loss_max?: number;
    /**
     * Most likely secondary loss ($)
     */
    secondary_loss_mode?: number;
    /**
     * Secondary loss event probability
     */
    slef_probability?: number;
    /**
     * Asset value ($)
     */
    asset_value?: number;
    /**
     * Monte Carlo iterations
     */
    iterations?: number;
};

