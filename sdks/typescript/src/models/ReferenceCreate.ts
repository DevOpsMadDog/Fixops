/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ReferenceCreate = {
    /**
     * ID of the artifact being referenced
     */
    referenced_artifact_id: string;
    /**
     * related | supersedes | implements | required_by
     */
    reference_type?: string;
    notes?: string;
};

