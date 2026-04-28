/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__incident_comms_router__CreateTemplateRequest = {
    /**
     * Unique template name (required)
     */
    template_name: string;
    /**
     * initial_notification | status_update | resolution | post_mortem | stakeholder_brief | press_release
     */
    comm_type?: string;
    /**
     * email | slack | teams | sms | pagerduty | status_page | internal
     */
    channel?: string;
    /**
     * Subject line template
     */
    subject_template?: (string | null);
    /**
     * Body template with placeholders
     */
    body_template?: (string | null);
    /**
     * Target audience
     */
    audience?: (string | null);
};

