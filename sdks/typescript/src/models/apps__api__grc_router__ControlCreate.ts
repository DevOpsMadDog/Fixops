/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__grc_router__ControlCreate = {
    framework_id: string;
    /**
     * e.g. CC6.1, A.9.1.1
     */
    control_ref?: string;
    title?: string;
    description?: string;
    category?: string;
    /**
     * implemented|partial|not_implemented|not_applicable
     */
    status?: string;
    evidence_count?: number;
    owner?: string;
    due_date?: (string | null);
};

