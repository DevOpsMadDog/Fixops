/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__backup_engine__BackupStatus } from './core__backup_engine__BackupStatus';
export type RestoreRecord = {
    id: string;
    backup_id: string;
    status: core__backup_engine__BackupStatus;
    restored_databases: Array<string>;
    started_at: string;
    completed_at?: (string | null);
    error?: (string | null);
};

