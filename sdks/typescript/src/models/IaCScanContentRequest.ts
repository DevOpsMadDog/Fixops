/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IaCProvider } from './IaCProvider';
/**
 * Request model for scanning IaC content.
 */
export type IaCScanContentRequest = {
    /**
     * IaC file content to scan
     */
    content: string;
    /**
     * Filename (used for provider detection)
     */
    filename: string;
    /**
     * IaC provider type (auto-detected if not specified)
     */
    provider?: (IaCProvider | null);
    /**
     * Scanner to use: 'checkov' or 'tfsec' (auto-selected if not specified)
     */
    scanner?: (string | null);
};

