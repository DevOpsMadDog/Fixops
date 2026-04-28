/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ParseRequest = {
    org_id?: string;
    /**
     * Customer-chosen ref, e.g. 'myapp@main'
     */
    repo_ref: string;
    /**
     * python | typescript | java
     */
    language: string;
    /**
     * Absolute path to repo root
     */
    root_path: string;
};

