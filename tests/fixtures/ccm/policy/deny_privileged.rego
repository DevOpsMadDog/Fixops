package main

import rego.v1

deny contains msg if {
    input.spec.containers[_].securityContext.privileged == true
    msg := "Container must not run as privileged"
}
