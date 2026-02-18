
package fixops

import rego.v1

# Require SBOM for deployment
allow if {
    input.sbom_present == true
    input.sbom_valid == true
}

# Check for required components
allow if {
    input.sbom_present == true
    required_fields := ["name", "version", "supplier"]
    every field in required_fields {
        input.sbom.metadata[field]
    }
}
