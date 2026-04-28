/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PackageInput = {
    /**
     * Package name
     */
    name: string;
    /**
     * Package version
     */
    version?: string;
    /**
     * Package manager (npm, pypi, maven)
     */
    package_manager?: string;
    /**
     * Days since first publish
     */
    age_days?: (number | null);
    /**
     * Total downloads
     */
    download_count?: (number | null);
    /**
     * Number of maintainers
     */
    maintainer_count?: (number | null);
    /**
     * Has build provenance attestation
     */
    has_provenance?: (boolean | null);
    /**
     * Recent ownership transfer
     */
    ownership_changed?: (boolean | null);
    /**
     * Days since last update
     */
    last_update_days?: (number | null);
};

