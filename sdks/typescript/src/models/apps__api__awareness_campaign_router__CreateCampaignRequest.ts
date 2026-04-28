/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__awareness_campaign_router__CreateCampaignRequest = {
    /**
     * Campaign title
     */
    title: string;
    /**
     * phishing_sim | training | quiz | newsletter | video | tabletop
     */
    campaign_type?: string;
    /**
     * draft | active | completed | paused | cancelled
     */
    campaign_status?: string;
    target_department?: (string | null);
    target_count?: (number | null);
    start_date?: (string | null);
    end_date?: (string | null);
    created_by?: (string | null);
};

