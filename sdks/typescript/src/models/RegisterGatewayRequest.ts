/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterGatewayRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Gateway name
     */
    name: string;
    /**
     * Base URL of the gateway
     */
    base_url: string;
    /**
     * kong | apigee | aws_api_gw | nginx | custom
     */
    gateway_type: string;
    /**
     * prod | staging | dev
     */
    environment?: string;
};

