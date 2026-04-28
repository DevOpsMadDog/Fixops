/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type BackupCreate = {
    org_id: string;
    system_name: string;
    backup_type?: string;
    backup_location?: string;
    immutable?: boolean;
    encrypted?: boolean;
    retention_days?: number;
};

