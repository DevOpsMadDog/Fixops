/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { OutputFormat } from './OutputFormat';
/**
 * Request body for /generate.
 */
export type apps__api__changelog_router__GenerateRequest = {
    /**
     * Raw commit log text. Each line may be plain commit messages or tabular format: <sha>\t<author>\t<date>\t<message>
     */
    commits: string;
    /**
     * Version label for this changelog
     */
    version?: string;
    /**
     * Output format
     */
    format?: OutputFormat;
};

