/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordVectorRequest = {
    /**
     * Short name for the threat vector
     */
    name: string;
    /**
     * network | email | supply_chain | insider | physical | social_engineering | zero_day | credential_stuffing
     */
    vector_type?: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    description?: (string | null);
    frequency_score?: (number | null);
    impact_score?: (number | null);
    first_observed?: (string | null);
    last_observed?: (string | null);
};

