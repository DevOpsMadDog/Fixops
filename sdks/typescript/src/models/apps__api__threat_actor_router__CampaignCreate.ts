/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_actor_router__CampaignCreate = {
    campaign_name: string;
    start_date?: string;
    end_date?: string;
    target_sectors?: Array<string>;
    target_regions?: Array<string>;
    ttps_used?: Array<string>;
    malware_families?: Array<string>;
    status?: string;
    impact_level?: string;
};

