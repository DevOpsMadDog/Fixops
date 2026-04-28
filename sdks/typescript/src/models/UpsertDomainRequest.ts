/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpsertDomainRequest = {
    /**
     * Domain identifier e.g. 'Vulnerability Management'
     */
    domain_name: string;
    /**
     * vulnerability | compliance | identity | network | endpoint | cloud | data | physical
     */
    domain_category: string;
    /**
     * Domain weight (0-1), clamped automatically
     */
    weight: number;
    /**
     * Current raw score
     */
    score: number;
    /**
     * Maximum possible score
     */
    max_score: number;
};

