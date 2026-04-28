/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_deception_management_router__CreateCampaignRequest = {
    /**
     * Campaign name
     */
    name: string;
    description?: string;
    /**
     * JSON array of decoy IDs
     */
    decoy_ids_json?: string;
    /**
     * Campaign objective
     */
    objective?: string;
    /**
     * active | paused | completed
     */
    status?: string;
    started_at?: (string | null);
    ended_at?: (string | null);
};

