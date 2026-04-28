/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterDependencyRequest = {
    org_id?: string;
    /**
     * Package name
     */
    package_name: string;
    /**
     * Package version
     */
    version: string;
    /**
     * Ecosystem: npm/pypi/maven/nuget/cargo/go/gem/composer/hex
     */
    ecosystem?: string;
    /**
     * SPDX license identifier
     */
    license?: string;
    /**
     * True=direct dep, False=transitive
     */
    direct?: boolean;
    /**
     * Dependency depth (0=direct)
     */
    depth?: number;
    /**
     * Parent package name if transitive
     */
    parent_package?: string;
};

