/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Generate a PR from a single security finding.
 */
export type GeneratePRRequest = {
    /**
     * Security finding dict (Snyk/Trivy/Grype/Dependabot shape)
     */
    finding: Record<string, any>;
    /**
     * Target repository name, e.g. 'Fixops'
     */
    repo: string;
    /**
     * GitHub owner or org, e.g. 'DevOpsMadDog'
     */
    owner: string;
    /**
     * Tenant identifier
     */
    org_id?: string;
};

