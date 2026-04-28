/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single component of the overall posture score.
 */
export type PostureComponent = {
    /**
     * Component identifier (e.g. 'vulnerability_density')
     */
    name: string;
    /**
     * Component score 0-100
     */
    score: number;
    /**
     * Fractional weight in overall score
     */
    weight: number;
    /**
     * Supporting metrics
     */
    details?: Record<string, any>;
};

