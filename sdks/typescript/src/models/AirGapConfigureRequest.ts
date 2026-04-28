/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for configuring air-gap mode settings.
 */
export type AirGapConfigureRequest = {
    /**
     * Air-gap mode: disabled | detected | configured | enforced
     */
    mode?: (string | null);
    /**
     * Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET
     */
    classification_level?: (string | null);
    /**
     * Allow LAN traffic (e.g. for local Ollama/vLLM)
     */
    allow_local_network?: (boolean | null);
    /**
     * Allow data import from removable media
     */
    allow_usb_import?: (boolean | null);
    /**
     * FIPS enforcement: disabled | audit | enforced
     */
    fips_mode?: (string | null);
    /**
     * Local LLM backend: ollama | vllm | llamacpp | huggingface_local | none
     */
    llm_backend?: (string | null);
    /**
     * URL for the local LLM API (e.g. http://localhost:11434)
     */
    llm_endpoint?: (string | null);
    /**
     * Model name to use (e.g. mistral:7b, llama3:8b)
     */
    llm_model?: (string | null);
    /**
     * List of scanner names to enable, or ['all'] for all 25
     */
    enabled_scanners?: (Array<string> | null);
    /**
     * Override paths for offline data (vuln_db, signatures, etc.)
     */
    offline_data_paths?: (Record<string, string> | null);
    /**
     * Operator/user making the configuration change
     */
    configured_by?: (string | null);
};

