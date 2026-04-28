/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ai_orchestrator_router__CreateTaskRequest = {
    /**
     * Agent role: analyst|reviewer|remediator|investigator|compliance_checker|threat_hunter
     */
    role: string;
    prompt: string;
    context?: Record<string, any>;
};

