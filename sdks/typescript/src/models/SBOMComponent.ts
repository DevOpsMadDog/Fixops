/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single component entry from an SBOM.
 */
export type SBOMComponent = {
    name: string;
    version?: string;
    license_expression?: (string | null);
    declared_licenses?: Array<string>;
    package_url?: (string | null);
    supplier?: (string | null);
    is_direct_dependency?: boolean;
};

