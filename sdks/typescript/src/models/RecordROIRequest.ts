/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordROIRequest = {
    /**
     * Budget category
     */
    category?: string;
    /**
     * Name of the security initiative
     */
    initiative_name: string;
    /**
     * Total investment amount
     */
    investment_amount: number;
    /**
     * Estimated risk reduction % (0-100)
     */
    estimated_risk_reduction: number;
    /**
     * ISO assessment date
     */
    assessment_date?: (string | null);
    /**
     * Optional notes
     */
    notes?: string;
};

