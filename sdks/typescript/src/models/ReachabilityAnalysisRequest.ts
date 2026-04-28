/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GitRepositoryRequest } from './GitRepositoryRequest';
import type { VulnerabilityRequest } from './VulnerabilityRequest';
/**
 * Request for reachability analysis.
 */
export type ReachabilityAnalysisRequest = {
    /**
     * Repository configuration
     */
    repository: GitRepositoryRequest;
    /**
     * Vulnerability details
     */
    vulnerability: VulnerabilityRequest;
    /**
     * Force repository refresh
     */
    force_refresh?: boolean;
    /**
     * Run analysis asynchronously
     */
    async_analysis?: boolean;
};

