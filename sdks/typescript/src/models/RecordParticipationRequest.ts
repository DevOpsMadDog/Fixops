/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordParticipationRequest = {
    /**
     * User ID of the participant
     */
    user_id: string;
    /**
     * pass | fail | incomplete | click | report
     */
    result: string;
    department?: (string | null);
    score?: (number | null);
    completed_at?: (string | null);
    time_spent_minutes?: (number | null);
};

