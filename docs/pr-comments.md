# Automatic pull-request summaries

The composite Action can publish one compact PR comment after a PASS or BLOCK. Publication is disabled by default. The `secguard` CLI still writes reports without contacting GitHub; `scripts/post_pr_comment.py` is a separate publisher used by the Action.

The public comment contains the verdict, active and waived counts, threshold, check date, and a link to the workflow attempt. It excludes finding paths, descriptions, rule names, waiver owners, scanner match text, and credential values. The publisher reads the fixed summary header and builds a new body; it never uploads the original Markdown report. Store detailed evidence in workflow artifacts with appropriate access and retention.

## Enable publication

Use `pull_request`, a trusted same-repository head, and a reviewed Action revision. Grant `pull-requests: write` only to the publishing job. This permission covers comment creation/update and the PR reads needed to verify its current head. A checkout also needs `contents: read`.

This example is for this repository's own workflow, where the reviewed toolkit is available through `uses: ./` and a trusted detector has already produced `reports/gitleaks.json`. For another repository, pin `lucashgrifoni/secrets-hygiene-kit` to a reviewed full commit SHA and set `comment-repository` to that consumer repository's fixed owner/name.

```yaml
on: pull_request
permissions:
  contents: read

jobs:
  trusted-secret-gate:
    if: >-
      github.event.pull_request.head.repo.full_name == github.repository &&
      github.actor == 'lucashgrifoni'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    concurrency:
      group: secguard-comment-${{ github.event.pull_request.number }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # Run the trusted detector before this step, preserving scan errors.
      - uses: ./
        id: secguard
        with:
          reports: reports/gitleaks.json
          publish-pr-comment: "true"
          comment-repository: lucashgrifoni/secrets-hygiene-kit
          comment-marker: secret-gate
```

Keep the normal gate enabled for other PRs, including forks, with publication disabled. A fork does not qualify for this publisher even if a workflow explicitly requests publication. Dependabot runs commonly have restricted tokens and should leave this option disabled. Do not switch to `pull_request_target`, expose a privileged token to fork code, or execute untrusted report content.

The Action uses the job's `github.token` through an environment variable. It has no token input and accepts no token argument. A missing token or insufficient permission fails publication. The publisher runs from the Action's own checkout with Python isolated mode, which ignores the consumer working directory and `PYTHONPATH` for imports.

## Inputs and outputs

| Input | Default | Contract |
| --- | --- | --- |
| `publish-pr-comment` | `false` | Set to `true` for the trusted PR job. Other values fail validation. |
| `comment-repository` | empty | Required when enabled; a literal `owner/repository` controlled by the workflow author. |
| `comment-marker` | `secguard` | Namespace for this gate: 1–40 lowercase letters, digits, underscores, or hyphens, beginning with a letter or digit. Use a distinct marker per publisher. |
| `comment-author` | `github-actions[bot]` | Bot login that owns the summary; the API must confirm its numeric identity and bot type. |
| `comment-output` | `secguard-comment.md` | Local compact report produced by the gate. Must remain enabled when publication is requested. |

| Output | Meaning |
| --- | --- |
| `verdict` | Original gate verdict. Publication never changes it. |
| `comment-status` | `created`, `updated`, `unchanged`, or `not-published`; empty when disabled or publication fails. |
| `comment-id` | Confirmed numeric comment ID; empty when no comment was confirmed. |

After BLOCK, the publisher still runs and can create or update the summary. A successful post leaves the Action failed with verdict BLOCK. If the publisher fails after PASS, the Action fails while `verdict` still identifies the gate's PASS; callers must check the Action outcome as well as its verdict. No completed gate decision means `not-published`; it does not make an earlier gate error successful. Cancellation skips publication.

## Update and replay rules

The publisher verifies the immutable Action PR context against the event file, the expected repository, and the current open PR returned by GitHub. Both head and base must belong to the expected repository. The current head is checked again after searching comments. An outdated head is rejected before mutation.

Only the configured bot's comment with the exact marker can be updated. Human comments and other markers remain intact. Identical content returns `unchanged` without a write. Multiple matching bot comments, an unknown publisher stamp, or incomplete pagination fails without selecting or creating another comment.

The hidden stamp records the head commit, run ID, attempt, workflow run number, and a hash of the workflow identity. A newer workflow run or attempt cannot be overwritten by an older one. Ordering uses `run_number`, which GitHub increments per workflow; it does not assume that `run_id` is ordered. A marker belonging to another workflow is rejected. The stamp and parser format are versioned as v1.

Serialize publishers for each PR and marker with workflow/job concurrency. GitHub comments do not provide a transaction covering head verification and mutation, so these checks do not guarantee atomic publication across concurrent jobs. The publisher does not delete duplicates or automatically retry writes. If delivery cannot be confirmed after a transport failure, the job fails; a rerun searches for the owned comment before attempting another post.

## Limits and supported endpoints

The publisher caps the summary input at 256 KiB, the event at 1 MiB, each HTTP response at 2 MiB, and its generated body at 2 KiB. It searches at most ten pages of thirty comments. If the last permitted page is full, publication fails rather than treating an incomplete search as proof that no summary exists. Requests have a 15-second timeout, verify TLS, reject redirects, require JSON and the expected HTTP status, and never print the token or response payload.

GitHub.com uses the exact `https://api.github.com` and `https://github.com` pair. GitHub Enterprise Server accepts only the canonical HTTPS server and its `/api/v3` endpoint supplied by the Actions runtime, on the default HTTPS port. Custom URL inputs, embedded credentials, extra paths, queries, and redirects are rejected. The API version is explicitly `2022-11-28`; a server that does not support it fails closed. Endpoint validation is tested; an Enterprise Server deployment still needs its own acceptance run.

The standalone script consumes the same environment contract as the Action. It is intended for trusted workflow orchestration, not a general command that accepts an arbitrary API endpoint or token on its command line. All error messages omit report content and credentials.

## References

- [GitHub issue and PR comment permissions and statuses](https://docs.github.com/en/rest/issues/comments)
- [Pull-request reads](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request)
- [Workflow context and run ordering](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)
- [Fork and Dependabot token restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)
- [REST API version support](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [GitHub Enterprise Server API](https://docs.github.com/en/enterprise-server@3.19/rest/using-the-rest-api/getting-started-with-the-rest-api)
