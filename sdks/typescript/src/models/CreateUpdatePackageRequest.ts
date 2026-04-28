/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create an offline update package.
 */
export type CreateUpdatePackageRequest = {
    /**
     * Type: vuln_db | signatures | compliance_rules | llm_model | full_system
     */
    package_type: string;
    /**
     * List of absolute server-side paths to include in the package
     */
    content_paths: Array<string>;
    /**
     * Package version string (e.g. 2024.11.1)
     */
    version: string;
    /**
     * Absolute output path for the generated ZIP package
     */
    output_path: string;
};

