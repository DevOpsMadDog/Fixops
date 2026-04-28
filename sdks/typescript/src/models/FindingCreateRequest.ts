/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FindingCreateRequest = {
    app_id: string;
    scan_id?: (string | null);
    vuln_type?: string;
    severity?: string;
    cwe_id?: string;
    description?: string;
    file_path?: string;
    line_number?: number;
    status?: string;
    owasp_category?: (string | null);
};

