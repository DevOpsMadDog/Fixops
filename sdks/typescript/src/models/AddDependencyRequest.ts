/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddDependencyRequest = {
    /**
     * Source package/component
     */
    source: string;
    /**
     * Target package/component
     */
    target: string;
    version?: (string | null);
    metadata?: Record<string, any>;
};

