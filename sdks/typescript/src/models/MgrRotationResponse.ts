/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MgrRotationResponse = {
    finding_id: string;
    category: string;
    rotation_steps: Array<string>;
    rotation_script: string;
    estimated_downtime_minutes: number;
    requires_service_restart: boolean;
    vault_path: (string | null);
    status: string;
    created_at: string;
};

