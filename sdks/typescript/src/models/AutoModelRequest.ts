/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AutoModelRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Design-doc ingest id
     */
    doc_ingest_id: string;
    /**
     * Override auto-generated model name
     */
    model_name?: (string | null);
    /**
     * Creator id / username
     */
    created_by?: string;
    /**
     * If provided, also write traceability link to this cyber model
     */
    link_cyber_model_id?: (string | null);
};

