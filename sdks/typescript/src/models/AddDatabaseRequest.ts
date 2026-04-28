/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Register a database in the inventory.
 */
export type AddDatabaseRequest = {
    name: string;
    /**
     * postgresql | mysql | mongodb | redis | mssql | oracle | sqlite
     */
    db_type: string;
    version?: string;
    host: string;
    port: number;
    tls_enabled?: boolean;
    tls_version?: (string | null);
    backup_enabled?: boolean;
    /**
     * ISO datetime of last backup
     */
    backup_last_run?: (string | null);
    backup_encrypted?: boolean;
    backup_offsite?: boolean;
    public_facing?: boolean;
    tags?: (Record<string, string> | null);
    metadata?: (Record<string, any> | null);
};

