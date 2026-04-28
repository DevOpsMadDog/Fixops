/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Register a developer as owner of a repository.
 */
export type RegisterRepoRequest = {
    /**
     * Repository name (e.g. my-org/my-repo)
     */
    repo_name: string;
    /**
     * Developer e-mail address
     */
    developer_email: string;
    /**
     * Organisation identifier
     */
    org_id: string;
};

