/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Risk posture response.
 */
export type RiskPostureResponse = {
    /**
     * Overall risk score 0-100
     */
    overall_score: number;
    /**
     * Per-category scores
     */
    category_scores: Record<string, number>;
    /**
     * improving/degrading/stable
     */
    trend: string;
    /**
     * Top risk factors
     */
    contributing_factors: Array<string>;
    /**
     * Mitigation recommendations
     */
    recommendations: Array<string>;
    /**
     * Assessment timestamp
     */
    timestamp: string;
};

