/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SetTrustScoreRequest = {
    entity_id: string;
    /**
     * user | device | service
     */
    entity_type?: string;
    trust_score: number;
    score_factors?: Record<string, any>;
};

