/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for exporting a sneakernet update package.
 */
export type SneakernetExportRequest = {
    /**
     * Absolute server-side paths of files to include in the package
     */
    payload_files: Array<string>;
    /**
     * Package type: cve_db | sbom | trustgraph_config | signatures | full_system
     */
    package_type: string;
    /**
     * Semantic version string, e.g. 2025.01.1
     */
    version: string;
    /**
     * 64-hex-char AES-256 key for encrypting the package
     */
    encryption_key_hex: string;
    /**
     * Classification level for the package
     */
    classification?: string;
    /**
     * Override output file path
     */
    output_path?: (string | null);
};

