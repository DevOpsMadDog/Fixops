/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateWorkflowIn = {
    /**
     * Workflow name
     */
    name: string;
    /**
     * vulnerability|alert|anomaly|policy_violation|incident|manual
     */
    trigger_type?: string;
    /**
     * JSON-serialized trigger rule
     */
    trigger_condition?: Record<string, any>;
    /**
     * patch|isolate|block|notify|script|api_call|rollback|quarantine
     */
    action_type?: string;
    /**
     * host|container|network|identity|application|cloud_resource
     */
    target_type?: string;
    /**
     * full|semi|manual
     */
    automation_level?: string;
};

