/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for adding a key result.
 */
export type KeyResultAdd = {
    title: string;
    /**
     * Goal value to reach
     */
    target_value: number;
    /**
     * Current measured value
     */
    current_value?: number;
    /**
     * Unit of measurement
     */
    unit?: string;
    due_date?: (string | null);
};

