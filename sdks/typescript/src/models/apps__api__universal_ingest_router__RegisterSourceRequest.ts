/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__universal_ingest_router__RegisterSourceRequest = {
    org_id: string;
    source_name: string;
    /**
     * Dict of {target_field: source_jsonpath}
     */
    schema_mapping?: Record<string, string>;
    enabled?: boolean;
};

