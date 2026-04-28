/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { VerificationStatus } from './VerificationStatus';
/**
 * Integrity verification record for a specific backup artifact.
 */
export type BackupVerification = {
    id?: string;
    backup_job_id: string;
    backup_artifact_path: string;
    sha256_checksum?: (string | null);
    checksum_verified?: boolean;
    restore_tested?: boolean;
    restore_test_result?: VerificationStatus;
    restore_test_duration_seconds?: (number | null);
    backup_age_hours?: (number | null);
    age_alert_triggered?: boolean;
    age_alert_threshold_hours?: number;
    verified_at?: (string | null);
    verified_by?: (string | null);
    notes?: (string | null);
    org_id?: string;
    created_at?: string;
};

