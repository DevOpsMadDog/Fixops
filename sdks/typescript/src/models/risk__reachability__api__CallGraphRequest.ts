/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for call graph analysis.
 */
export type risk__reachability__api__CallGraphRequest = {
    /**
     * Local path to repository
     */
    repo_path: string;
    /**
     * Function to check reachability for
     */
    target_function?: (string | null);
};

