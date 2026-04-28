/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__sso_router__SessionResponse = {
    authenticated: boolean;
    email?: (string | null);
    name?: (string | null);
    roles?: Array<string>;
    groups?: Array<string>;
    provider?: (string | null);
    sub?: (string | null);
};

