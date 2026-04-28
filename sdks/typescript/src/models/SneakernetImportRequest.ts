/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for importing a sneakernet update package.
 */
export type SneakernetImportRequest = {
    /**
     * Absolute path to the .snk package file on the server
     */
    package_path: string;
    /**
     * 64-hex-char AES-256 key that was used when exporting
     */
    encryption_key_hex: string;
    /**
     * Override extraction directory
     */
    extract_dir?: (string | null);
};

