/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /images/analyse — analyse a container image from manifest/config blobs.
 */
export type ImageAnalysisRequest = {
    image_ref: string;
    manifest?: (Record<string, any> | null);
    config?: (Record<string, any> | null);
};

