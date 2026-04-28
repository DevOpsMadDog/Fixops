/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__threat_modeling_router__GenerateRequest = {
    /**
     * Feature/system name
     */
    name: string;
    /**
     * Feature/system description
     */
    description: string;
    /**
     * Component names (e.g. 'web-frontend', 'api-gateway', 'database')
     */
    components: Array<string>;
    /**
     * Data flows (e.g. 'user->api->db')
     */
    data_flows?: Array<string>;
    /**
     * Filter to specific STRIDE categories
     */
    stride_filter?: (Array<string> | null);
};

