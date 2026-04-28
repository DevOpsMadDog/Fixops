/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddFindingBody = {
    /**
     * Component with the finding
     */
    component: string;
    /**
     * design-flaw | missing-control | weak-implementation | configuration | dependency-risk | data-exposure
     */
    finding_type: string;
    /**
     * Short finding title
     */
    title: string;
    /**
     * Detailed description
     */
    description?: string;
    /**
     * critical | high | medium | low | info
     */
    severity?: string;
    /**
     * Remediation recommendation
     */
    recommendation?: string;
};

