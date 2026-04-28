/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to update dependencies.
 */
export type DependencyUpdateRequest = {
    sbom_id?: (string | null);
    package_ids?: Array<string>;
    /**
     * patch, minor, major, latest
     */
    update_strategy?: string;
};

