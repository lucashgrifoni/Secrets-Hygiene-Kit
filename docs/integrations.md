# OPA and DefectDojo

secguard 0.5.0 exports files for these consumers. Run the external tool separately,
with permissions appropriate to your environment. The CLI stays offline.

## OPA

```console
secguard scan check --input findings.json --opa-input opa-input.json
secguard policy show --output secguard.rego
opa eval --fail --data secguard.rego --input opa-input.json 'true = data.secguard.allow'
```

Preserve the secguard exit status as a gate. Valid exports are written even when
findings block, so external policy can evaluate the same decision. The
`secguard.policy-input/v1` snapshot includes the check date, threshold, gate,
expired waiver IDs and each finding's reconciled status and matching waiver IDs.

The Rego v1 example requires a passing secguard gate, no expired waiver and no
active Medium, High or Critical finding. A valid, fully scoped waiver can permit
a finding. The example strengthens the default High threshold; review changes
alongside your exception process. Input data does not authenticate a detector
or a waiver approver.

Use unification, `true = data.secguard.allow`, as shown. OPA's `--fail` rejects
an undefined query; a defined boolean `false` by itself does not fail. Policy
parse/compile errors must also block. Actual OPA 1.21.1 validation covered 16
allow, deny, invalid-input, expired-waiver, valid-waiver, compilation-error and
undefined-query cases. Repeat after installing secguard and a reviewed OPA:

```console
python scripts/validate_opa.py --opa PATH_TO_OPA --result opa-validation.json
```

See the [OPA CLI reference](https://www.openpolicyagent.org/docs/cli).

## DefectDojo

```console
secguard scan check --input findings.json --defectdojo defectdojo.json
```

Choose **Generic Findings Import**. In the tested DefectDojo 3.4.0, the report's
`type: secguard` creates **secguard Scan (Generic Findings Import)**. Active
findings include severity, file, line, date, a response command and a stable
`unique_id_from_tool`, derived from type, path and line. Corroboration by another
detector preserves that identifier. Moving the path or line can create a new one.

`verified: false` records that human triage has not been established in DefectDojo.
Credential verification remains an imported detector claim in the description.
A detector's `true` raises exported severity to Critical; it does not establish
DefectDojo triage.

Configure stable-ID matching for this Test Type on the importing application
and worker processes in Community Edition:

```text
DD_DEDUPLICATION_ALGORITHM_PER_PARSER={"secguard Scan (Generic Findings Import)":"unique_id_from_tool"}
```

The default hash-based matching can create duplicates when descriptions change,
even with an unchanged identifier. Apply this consumer setting before initial
import; review matching before reimporting historical scans in an existing instance.

Reuse the same Test. Set **Close old findings** to **false**
(`close_old_findings=false` through the API), and preserve existing triage.
Waived findings are omitted from exports. Omission or an empty report does not
prove remediation and must not close findings automatically.

The tested 3.4.0 reimport retains an existing finding's severity rather than
synchronizing it from a changed report. Compare exported and stored severities
and review changes before treating the consumer as current. The secguard gate
independently evaluates current severity. Initial High/Critical imports,
stable reimport, corroboration without duplicates, waiver/empty-report omission
and unauthenticated rejection were exercised on an owned local instance with
synthetic data. No external adopter or production instance was involved.

The optional script creates synthetic products in an owned local Docker pilot.
It requires a `uwsgi` service, synthetic account `secguard_pilot`, the matching
setting above and a loopback endpoint at port 18087:

```console
python scripts/validate_defectdojo.py --compose-file PATH_TO_LOCAL_COMPOSE --result defectdojo-validation.json
```

Prepare the pilot using the pinned consumer's installation documentation.
Use this script only with a disposable local instance. See
[Generic Findings Import](https://docs.defectdojo.com/supported_tools/parsers/file/generic/)
and [deduplication guidance](https://docs.defectdojo.com/supported_tools/parsers/generic_findings_import/).
