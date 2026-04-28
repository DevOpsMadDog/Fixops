/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Predicted response time.
 */
export type ResponseTimePrediction = {
    predicted_ms: number;
    historical_avg_ms?: (number | null);
    confidence: number;
    method?: string;
};

