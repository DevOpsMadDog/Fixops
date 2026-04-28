/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type _RegisterArtifactRequest = {
    name: string;
    version: string;
    commit_sha: string;
    artifact_type?: string;
    sha256?: (string | null);
    builder?: string;
    build_url?: (string | null);
    size_bytes?: number;
    metadata?: Record<string, any>;
};

