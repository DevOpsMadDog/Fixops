/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__sbom_export_router__GenerateRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Project name
     */
    project_name: string;
    /**
     * SBOM version tag
     */
    version_tag?: string;
    /**
     * Exporting user/system
     */
    exported_by?: string;
};

