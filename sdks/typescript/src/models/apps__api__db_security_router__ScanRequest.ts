/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Trigger a full security scan for a registered database.
 */
export type apps__api__db_security_router__ScanRequest = {
    db_id: string;
    /**
     * List of user records for privilege audit
     */
    users?: null;
    /**
     * Database schema (table/column list) for data exposure detection
     */
    schema?: null;
    /**
     * Query audit log entries for suspicious query detection
     */
    query_logs?: null;
    /**
     * Active TLS cipher suites for connection security assessment
     */
    cipher_suites?: (Array<string> | null);
    /**
     * TLS certificate expiry (ISO datetime)
     */
    cert_expiry?: (string | null);
    cert_valid?: (boolean | null);
    mutual_tls?: boolean;
};

