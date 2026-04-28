/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__backup_engine__BackupType } from './core__backup_engine__BackupType';
export type ScheduleRequest = {
    backup_type?: core__backup_engine__BackupType;
    frequency?: string;
    retention_days?: number;
};

