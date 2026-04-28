/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterPipelineRequest = {
    /**
     * Human-readable pipeline name
     */
    name: string;
    /**
     * siem | edr | ndr | cloud | api | database | file | streaming
     */
    source_type?: string;
    /**
     * Source URL or connection string
     */
    source_endpoint?: (string | null);
    /**
     * json | cef | leef | syslog | csv | parquet | avro
     */
    data_format?: string;
    /**
     * JSON string of field mapping / transformation rules
     */
    transformation_rules_json?: (string | null);
    /**
     * Destination system or topic
     */
    destination?: (string | null);
};

