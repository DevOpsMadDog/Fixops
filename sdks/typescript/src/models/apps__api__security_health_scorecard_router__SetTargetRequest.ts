/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_health_scorecard_router__SetTargetRequest = {
    /**
     * Domain name to set target for
     */
    domain_name: string;
    /**
     * Target score to achieve
     */
    target_score: number;
    /**
     * Current score baseline
     */
    current_score: number;
    /**
     * Target deadline (YYYY-MM-DD)
     */
    deadline: string;
    /**
     * Owner responsible for achieving target
     */
    owner?: string;
};

