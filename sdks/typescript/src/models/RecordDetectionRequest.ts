/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordDetectionRequest = {
    /**
     * Name of the detection
     */
    detection_name: string;
    /**
     * anomaly_detection | classification | nlp | graph_ml | time_series | rule_based | ensemble
     */
    model_type?: string;
    confidence_score?: number;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * logs | network | endpoint | identity | cloud | email | file
     */
    source_data_type?: string;
};

