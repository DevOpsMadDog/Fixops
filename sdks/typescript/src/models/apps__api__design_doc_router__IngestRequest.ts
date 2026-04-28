/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__design_doc_router__IngestRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Where the doc came from (URL / path)
     */
    doc_source: string;
    /**
     * Raw doc text (markdown or plain)
     */
    doc_content: string;
    /**
     * markdown|text|rst
     */
    doc_format?: string;
};

