/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__servicenow_sync_router__FieldMappingItem = {
    /**
     * Field name in the ALDECI finding dict
     */
    finding_field: string;
    /**
     * Field name in the ServiceNow incident record
     */
    sn_field: string;
    /**
     * Optional transform key: severity_to_urgency | severity_to_impact | status_to_state
     */
    transform?: (string | null);
};

