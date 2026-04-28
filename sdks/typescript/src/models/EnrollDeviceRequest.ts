/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EnrollDeviceRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Device display name
     */
    name: string;
    /**
     * Device platform: ios/android/windows/macos
     */
    platform: string;
    /**
     * Device serial number
     */
    serial_number?: string;
    /**
     * Operating system version
     */
    os_version?: string;
};

