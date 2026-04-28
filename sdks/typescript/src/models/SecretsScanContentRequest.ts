/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for scanning content for secrets.
 */
export type SecretsScanContentRequest = {
    /**
     * File content to scan
     */
    content: string;
    /**
     * Filename
     */
    filename: string;
    /**
     * Repository name
     */
    repository?: string;
    /**
     * Branch name
     */
    branch?: string;
    /**
     * Scanner to use: 'gitleaks' or 'trufflehog' (auto-selected if not specified)
     */
    scanner?: (string | null);
};

