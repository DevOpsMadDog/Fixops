/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__risk_quantification_router__TreatmentCreate = {
    /**
     * Parent scenario ID
     */
    scenario_id: string;
    /**
     * accept/mitigate/transfer/avoid
     */
    treatment_type?: string;
    /**
     * Treatment description
     */
    description?: string;
    /**
     * Implementation cost ($)
     */
    cost?: number;
    /**
     * Expected risk reduction (%)
     */
    risk_reduction_pct?: number;
    /**
     * proposed/approved/implemented
     */
    status?: string;
};

