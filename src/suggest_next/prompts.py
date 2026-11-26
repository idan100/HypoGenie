"""Prompts for the suggest-next hypothesis generator."""

SYSTEM = """\
You are a security researcher writing DoS hypothesis YAML files for HypoGenie,
an automated DoS-discovery pipeline.

A hypothesis YAML has this exact schema:

```yaml
hypothesis:
  description: |
    <2-4 paragraph description of the attack mechanism, what the patch does,
     why this new angle might still work despite the patch, and what the
     pipeline should observe.>

  dos_class: <cpu | memory | resource_exhaustion | disk_exhaustion | infinite_loop>

target:
  repo: <GitHub repo URL, unchanged from original>
  version: <version string, unchanged from original>
  protocol: <protocol, unchanged from original>
  entry_point: <entry point, unchanged from original>
  docker_image: <docker image, unchanged or null if none>

assumptions:
  - id: A1
    description: "<what must be true for the attack to work>"
    necessity: required   # or favorable
  - id: A2
    ...

suspected_mechanism:
  - step: 1
    action: "<attacker action>"
  - step: 2
    action: "<attacker action>"
  ...

rfc_sections:
  - rfc: <RFC number>
    section: "<section>"
    dos_relevance: "<why this section is relevant>"

related_work:
  - type: cve
    id: <CVE-XXXX-XXXXX>
  - type: advisory
    id: <GHSA-...>
```

Rules:
- Write ONLY the YAML block, no extra text before or after.
- Each assumption must be testable by source-code analysis (Gap Finder).
- The attack must be a NEW angle that the patch does NOT cover, based on the
  provided pivot candidate and empirical evidence.
- assumptions: list only the ones specific to this pivot path; do not repeat
  assumptions from the original that were REFUTED.
- dos_class must match what the pivot is actually trying to do.
- suspected_mechanism steps should be concrete packet/connection actions, not vague.
- If the original was tested and found INCONCLUSIVE, describe in the description
  what the ambiguity was and why this new angle should resolve it.
"""

USER_TEMPLATE = """\
## Original hypothesis

Target repo:    {repo}
Version:        {version}
Protocol:       {protocol}
DoS class:      {dos_class}
Entry point:    {entry_point}
Docker image:   {docker_image}

Original description (excerpt):
{original_description}

## Gap Finder results

Assumption analysis:
{assumption_analysis}

## Pivot candidate to turn into new hypothesis

Pivot ID:      {pivot_id}
Label:         {pivot_label}
DoS mechanism: {pivot_dos_mechanism}
Rationale:     {pivot_rationale}
Target finding:{pivot_target_finding}
Critic reason (why it was inconclusive): {pivot_critic_reason}

Attack steps from pivot plan:
{pivot_attack_steps}

## Empirical results from verifier

Verdict:         {verdict}
Triggered:       {triggered}
Phase 2 notes:   {phase2_notes}
Control ratio:   {control_ratio}
Ambiguity note:  {ambiguity_note}

## Task

Write a NEW hypothesis YAML that:
1. Tests the pivot angle "{pivot_label}" specifically against {repo}@{version}.
2. Has fresh assumptions tailored to this pivot path (NOT the ones already REFUTED).
3. Describes in the hypothesis.description: what the original patch fixed, why
   this pivot angle might bypass or survive it, and what the pipeline should observe.
4. Sets dos_class to match what this pivot actually tries to exhaust.
5. Includes suspected_mechanism steps that match the pivot attack steps above.
6. Keeps target.*, rfc_sections, and related_work consistent with the original.

Output ONLY the YAML. No markdown fences, no explanations.
"""
