/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_posture_scoring_router__RegisterControlRequest = {
    /**
     * Control name
     */
    name: string;
    /**
     * identity | network | endpoint | cloud | application | data | governance
     */
    domain?: string;
    description?: string;
    /**
     * Relative importance weight
     */
    weight?: number;
    /**
     * implemented | partial | not_implemented | compensating
     */
    control_status?: string;
    evidence_url?: string;
    last_assessed?: (string | null);
};

