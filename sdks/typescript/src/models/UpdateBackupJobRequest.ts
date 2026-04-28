/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__backup_validator__BackupStatus } from './core__backup_validator__BackupStatus';
import type { EncryptionType } from './EncryptionType';
export type UpdateBackupJobRequest = {
    name?: (string | null);
    status?: (core__backup_validator__BackupStatus | null);
    last_run_at?: (string | null);
    last_run_size_bytes?: (number | null);
    last_run_duration_seconds?: (number | null);
    next_run_at?: (string | null);
    retention_days?: (number | null);
    encryption?: (EncryptionType | null);
    tags?: (Array<string> | null);
    metadata?: (Record<string, any> | null);
};

