/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__grc_router__RiskCreate = {
    title: string;
    /**
     * strategic|operational|compliance|financial|reputational
     */
    category?: string;
    likelihood?: number;
    impact?: number;
    /**
     * accept|mitigate|transfer|avoid
     */
    treatment?: string;
    owner?: string;
    /**
     * open|mitigated|accepted|closed
     */
    status?: string;
    notes?: string;
};

