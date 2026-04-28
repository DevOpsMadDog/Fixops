/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__backup_validator__BackupStatus } from './core__backup_validator__BackupStatus';
import type { core__backup_validator__BackupType } from './core__backup_validator__BackupType';
import type { EncryptionType } from './EncryptionType';
export type RegisterBackupJobRequest = {
    /**
     * Descriptive name for the backup job
     */
    name: string;
    /**
     * Logical system being backed up
     */
    system_name: string;
    /**
     * Backup type
     */
    backup_type?: core__backup_validator__BackupType;
    /**
     * Source path, DB name, or bucket URI
     */
    source_path: string;
    /**
     * Destination storage URI or path
     */
    destination: string;
    /**
     * Cron expression (e.g. '0 2 * * *')
     */
    schedule_cron: string;
    /**
     * Retention period in days
     */
    retention_days?: number;
    /**
     * Encryption in transit/at rest
     */
    encryption?: EncryptionType;
    /**
     * Current job status
     */
    status?: core__backup_validator__BackupStatus;
    last_run_at?: (string | null);
    last_run_size_bytes?: (number | null);
    next_run_at?: (string | null);
    tags?: Array<string>;
    metadata?: Record<string, any>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

