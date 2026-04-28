/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddSectionRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Section name
     */
    section_name: string;
    /**
     * summary/risk/compliance/incidents/vulnerabilities/recommendations/kpis
     */
    section_type?: string;
    /**
     * Section content / narrative
     */
    content?: string;
    /**
     * Section score 0-100
     */
    score?: number;
    /**
     * Display order
     */
    sort_order?: number;
};

