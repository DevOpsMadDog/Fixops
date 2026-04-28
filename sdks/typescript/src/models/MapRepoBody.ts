/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MapRepoBody = {
    /**
     * Absolute path to repo on disk
     */
    repo_path: string;
    /**
     * Override service name (defaults to repo dir name)
     */
    service_name?: (string | null);
    /**
     * critical | high | medium | low
     */
    criticality?: string;
};

