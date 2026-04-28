/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordPermissionChangeRequest = {
    org_id?: string;
    identity_id: string;
    change_type?: string;
    permission_name: string;
    changed_by?: string;
    changed_at?: (string | null);
    approved?: boolean;
};

