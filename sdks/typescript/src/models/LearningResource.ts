/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Educational resource linked to a finding type.
 */
export type LearningResource = {
    title: string;
    url: string;
    /**
     * One of: OWASP, CWE, best-practice
     */
    category: string;
    finding_types: Array<string>;
};

