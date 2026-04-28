/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RunHuntRequest = {
    /**
     * Built-in or custom query ID
     */
    query_id: string;
    findings?: Array<Record<string, any>>;
    /**
     * IOC list for correlation
     */
    iocs?: null;
};

