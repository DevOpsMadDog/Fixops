/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to log a security activity for neglect zone tracking.
 */
export type LogActivityRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Component / service name
     */
    component: string;
    /**
     * Type of activity: scan, review, drill, pentest, audit
     */
    activity_type: string;
    /**
     * Activity description
     */
    description?: string;
    /**
     * Who performed the activity
     */
    actor?: (string | null);
    /**
     * Does this component hold critical data?
     */
    has_critical_data?: boolean;
};

