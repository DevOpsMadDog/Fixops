/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__backup_validator__BackupStatus } from './core__backup_validator__BackupStatus';
import type { core__backup_validator__BackupType } from './core__backup_validator__BackupType';
import type { EncryptionType } from './EncryptionType';
/**
 * Tracks a single backup job definition and its current state.
 */
export type BackupJob = {
    id?: string;
    name: string;
    system_name: string;
    backup_type?: core__backup_validator__BackupType;
    source_path: string;
    destination: string;
    schedule_cron: string;
    retention_days?: number;
    encryption?: EncryptionType;
    status?: core__backup_validator__BackupStatus;
    last_run_at?: (string | null);
    last_run_size_bytes?: (number | null);
    last_run_duration_seconds?: (number | null);
    next_run_at?: (string | null);
    tags?: Array<string>;
    metadata?: Record<string, any>;
    org_id?: string;
    created_at?: string;
    updated_at?: string;
};

