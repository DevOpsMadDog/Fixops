/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to mint a disposable scoped token.
 */
export type DisposableTokenCreate = {
    scope: Array<string>;
    ttl_seconds: number;
    purpose: string;
};

