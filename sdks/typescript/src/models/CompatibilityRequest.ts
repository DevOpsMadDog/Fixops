/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for license compatibility check.
 */
export type CompatibilityRequest = {
    /**
     * SPDX ID of the project license
     */
    project_license: string;
    /**
     * SPDX ID of the dependency license
     */
    dependency_license: string;
};

