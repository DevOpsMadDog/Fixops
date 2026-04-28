/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type StartRunRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Repository reference (org/repo)
     */
    repo_ref: string;
    /**
     * CI provider's native run ID
     */
    run_id_external?: string;
    /**
     * github-actions|gitlab-ci|jenkins|circleci|azure-devops|argo|tekton|other
     */
    ci_provider: string;
    /**
     * push|pull_request|schedule|manual|tag
     */
    trigger?: string;
    branch?: string;
    /**
     * Git commit SHA
     */
    commit_sha?: string;
};

