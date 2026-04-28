/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__backup_engine__BackupStatus } from './core__backup_engine__BackupStatus';
import type { core__backup_engine__BackupType } from './core__backup_engine__BackupType';
export type BackupRecord = {
    id: string;
    type: core__backup_engine__BackupType;
    status: core__backup_engine__BackupStatus;
    databases: Array<string>;
    file_path: string;
    file_size_bytes: number;
    checksum: string;
    encrypted: boolean;
    created_at: string;
    completed_at?: (string | null);
    retention_days: number;
    org_id: string;
};

