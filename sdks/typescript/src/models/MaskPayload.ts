/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /mask — mask sensitive data in the supplied text.
 */
export type MaskPayload = {
    content: string;
    categories?: (Array<string> | null);
    tokenize?: boolean;
};

