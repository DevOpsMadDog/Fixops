/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordAccessIn = {
    /**
     * Identity/service that accessed the secret
     */
    accessor: string;
    /**
     * Action performed (read|write|delete|rotate)
     */
    action: string;
};

