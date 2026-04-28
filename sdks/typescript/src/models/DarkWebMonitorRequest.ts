/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DarkWebMonitorRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Subsidiary to monitor on dark-web sources
     */
    subsidiary_name: string;
    /**
     * Keywords (brands, email domains, product names) to watch for
     */
    keywords?: Array<string>;
};

