/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DevTokenUser } from './DevTokenUser';
/**
 * Response from /api/v1/auth/dev-token.
 */
export type DevTokenResponse = {
    access_token: string;
    token_type?: string;
    expires_in?: number;
    user: DevTokenUser;
};

