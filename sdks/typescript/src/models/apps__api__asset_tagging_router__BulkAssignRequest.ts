/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__asset_tagging_router__BulkAssignRequest = {
    /**
     * List of asset_ids to tag
     */
    asset_ids: Array<string>;
    /**
     * Tag ID to assign to all assets
     */
    tag_id: string;
    assigned_by?: string;
};

