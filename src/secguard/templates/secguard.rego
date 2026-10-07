package secguard

import rego.v1

# Example organizational threshold: medium. Customize in a reviewed policy.
# This policy never authorizes a gate that secguard itself blocked.
default allow := false

ranks := {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

allow if {
    input.schema == "secguard.policy-input/v1"
    input.gate.passed == true
    is_array(input.gate.expired_waivers)
    count(input.gate.expired_waivers) == 0
    is_array(input.findings)
    every finding in input.findings {
        valid_finding(finding)
    }
}

valid_finding(finding) if {
    finding.status == "waived"
    is_array(finding.waiver_ids)
    count(finding.waiver_ids) > 0
    ranks[finding.severity] >= 0
}

valid_finding(finding) if {
    finding.status == "active"
    ranks[finding.severity] < ranks.medium
}
