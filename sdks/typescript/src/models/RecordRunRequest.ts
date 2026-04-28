/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordRunRequest = {
    /**
     * queued | running | completed | failed | partial
     */
    run_status: string;
    /**
     * Records read from source
     */
    records_in?: number;
    /**
     * Records successfully processed
     */
    records_out?: number;
    /**
     * Records that failed processing
     */
    records_failed?: number;
    /**
     * Wall-clock duration of the run
     */
    duration_seconds?: number;
    /**
     * Error detail if run failed
     */
    error_message?: (string | null);
    /**
     * ISO-8601 run start time
     */
    started_at?: (string | null);
    /**
     * ISO-8601 run completion time
     */
    completed_at?: (string | null);
};

