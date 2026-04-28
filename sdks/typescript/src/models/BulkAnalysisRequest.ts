/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GitRepositoryRequest } from './GitRepositoryRequest';
import type { VulnerabilityRequest } from './VulnerabilityRequest';
/**
 * Request for bulk analysis.
 */
export type BulkAnalysisRequest = {
    repository: GitRepositoryRequest;
    vulnerabilities: Array<VulnerabilityRequest>;
    async_analysis?: boolean;
};

