/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddQueryBody = {
    /**
     * Human-readable query name
     */
    query_name: string;
    /**
     * KQL | SPL | SQL | EQL | YARA | sigma | lucene
     */
    query_language?: string;
    /**
     * Query body/content
     */
    query_content?: string;
    /**
     * siem | edr | network | cloud | identity | application
     */
    data_source?: string;
};

