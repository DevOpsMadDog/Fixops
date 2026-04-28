/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cmdb_router__RecordChangeRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * CI that was changed
     */
    ci_id: string;
    /**
     * created | updated | decommissioned | patched | config_change | incident
     */
    change_type: string;
    /**
     * Human-readable change description
     */
    description?: string;
    /**
     * User or system that made the change
     */
    changed_by?: string;
    /**
     * ISO-8601 effective change date
     */
    change_date?: (string | null);
};

