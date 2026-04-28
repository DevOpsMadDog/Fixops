/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AutoFixOnPRRequest = {
    org_id: string;
    installation_id: string;
    /**
     * owner/repo
     */
    repo: string;
    pr_number: number;
    head_sha?: (string | null);
    /**
     * Vulnerability findings (engine accepts Snyk/Trivy/Grype/Dependabot shapes).
     */
    findings?: Array<Record<string, any>>;
    /**
     * If true, do not POST to GitHub.
     */
    dry_run?: boolean;
    max_fixes?: number;
    repo_context?: Record<string, any>;
};

