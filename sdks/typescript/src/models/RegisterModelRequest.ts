/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterModelRequest = {
    /**
     * Human-readable model name
     */
    model_name: string;
    /**
     * anomaly_detection | classification | nlp | graph_ml | time_series | ensemble
     */
    model_type?: string;
    accuracy_score?: number;
    false_positive_rate?: number;
    version?: string;
    training_data_size?: number;
    deployed_at?: (string | null);
    last_retrained?: (string | null);
};

