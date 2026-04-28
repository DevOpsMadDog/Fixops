/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ArtifactRegister = {
    /**
     * Name of the security artifact
     */
    artifact_name: string;
    /**
     * policy | standard | procedure | guideline | control | framework | tool | runbook
     */
    artifact_type?: string;
    version?: string;
    /**
     * draft | active | deprecated | under_review | archived
     */
    artifact_status?: string;
    description?: string;
    owner?: string;
    review_date?: (string | null);
    next_review_date?: (string | null);
    reviewer?: string;
    download_url?: string;
    tag_list?: Array<string>;
};

