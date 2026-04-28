/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateCommRequest = {
    /**
     * Associated incident ID
     */
    incident_id?: (string | null);
    /**
     * initial_notification | status_update | resolution | post_mortem | stakeholder_brief | press_release
     */
    comm_type?: string;
    /**
     * email | slack | teams | sms | pagerduty | status_page | internal
     */
    channel?: string;
    /**
     * Communication subject (required)
     */
    subject: string;
    /**
     * Communication body content (required)
     */
    body: string;
    /**
     * internal | external | executive | technical | customer | all
     */
    audience?: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * draft | sent | delivered | failed
     */
    comm_status?: string;
    /**
     * Scheduled send time (ISO 8601)
     */
    scheduled_at?: (string | null);
    /**
     * Author name or ID
     */
    author?: (string | null);
};

