/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cyber_insurance_router__PolicyIn = {
    carrier?: string;
    policy_number?: string;
    coverage_type?: string;
    coverage_limit?: number;
    deductible?: number;
    premium_annual?: number;
    effective_date?: string;
    expiry_date?: string;
    status?: string;
    covered_events?: Array<string>;
};

