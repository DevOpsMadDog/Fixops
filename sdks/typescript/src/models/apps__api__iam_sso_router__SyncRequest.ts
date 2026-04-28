/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__iam_sso_router__SyncRequest = {
    /**
     * Realm/org_id prefix; e.g. 'tenant' -> tenant-001..N
     */
    org_id_prefix?: string;
    /**
     * How many realms to provision (default 15)
     */
    realm_count?: number;
    /**
     * Skip Keycloak entirely; emit synthetic events
     */
    force_synthetic?: boolean;
};

