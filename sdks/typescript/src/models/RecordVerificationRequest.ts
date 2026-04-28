/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { VerificationStatus } from './VerificationStatus';
export type RecordVerificationRequest = {
    /**
     * Backup job this verification covers
     */
    backup_job_id: string;
    /**
     * Path or URI to the backup artifact
     */
    backup_artifact_path: string;
    /**
     * SHA-256 hash of the artifact
     */
    sha256_checksum?: (string | null);
    /**
     * Was the checksum validated?
     */
    checksum_verified?: boolean;
    /**
     * Was a restore test performed?
     */
    restore_tested?: boolean;
    restore_test_result?: VerificationStatus;
    restore_test_duration_seconds?: (number | null);
    /**
     * Age of the backup in hours
     */
    backup_age_hours?: (number | null);
    /**
     * Hours before age alert fires
     */
    age_alert_threshold_hours?: number;
    verified_by?: (string | null);
    notes?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: string;
};

