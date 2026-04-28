/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SignRequest = {
    /**
     * Content to sign (base64 or UTF-8)
     */
    content: string;
    /**
     * Key ID (auto-selects default)
     */
    key_id?: (string | null);
    /**
     * Content type label
     */
    content_type?: string;
};

