# ADR 0003 — Lineage-based masking, value scanning with Presidio, and closing predicate oracles

- Status: accepted
- Date: 2026-11-11

## Context

Personal data must not reach the model in clear. The model's output, and anything it can send onward, is
outside our control. KVKK (Kişisel Verilerin Korunması Kanunu, the Turkish data-protection law) treats TCKN
(national id), health data and contact data as personal data. Three facts make masking by column name
insufficient:

1. **Laundering.** `SELECT tckn AS x`, `UPPER(email)`, `SUBSTR(tckn,1,6) || SUBSTR(tckn,7)`, a derived table,
   a CTE or a UNION branch all move a classified value into an output column with another name.
2. **Free text.** Staff type phone numbers and TCKNs into notes columns that no classification knows about.
3. **Oracles.** A column can be masked in the output and still leak through a predicate:
   `WHERE tckn LIKE '1%'` answers yes/no questions, and around 40 questions recover a TCKN. `ORDER BY tckn`,
   `COUNT(CASE WHEN tckn LIKE …)`, `HAVING MAX(tckn) > '5'`, a JOIN on tckn and
   `'…' IN (SELECT tckn …)` do the same.

## Options considered

- **Mask by output column name.** Defeated by an alias.
- **Mask by value only (regex/NER on every cell).** Misses classified values that do not look like PII
  (a pseudonymised name, a birth date) and costs a detector run on every cell.
- **Database-side dynamic masking** (PostgreSQL Anonymizer, Oracle Data Redaction). Engine-specific. Oracle
  Data Redaction is a licensed option. Predicate-oracle behaviour varies by implementation.
- **Lineage from the guard's AST plus value scanning, with predicate rules.** Chosen.

## Decision

**Column masking from lineage.** For every output column the binder computes the set of classified source
columns its value depends on. That includes implicit flows: a CASE result depends on its WHEN conditions. A
*direct* reference (the column itself, through any number of aliases, derived tables, CTEs or same-column UNION
branches) gets the column's policy strategy:

| Strategy | Example | When |
|---|---|---|
| `Partial` (keep last N, never more than half) | `*********46` | identifiers where the tail helps humans match records |
| `Pseudonym` (HMAC-SHA-256, keyed) | `person_1f3a9c0b2e7d` | names: lets the agent count distinct people and join rows without seeing them; keyed, so the 10⁹ TCKN space cannot be brute-forced offline |
| `Redact` | `[EMAIL]` | default |
| `Null` | `null` | when even the presence of a value is sensitive |

Anything **computed** from a classified column (`UPPER`, `MIN`, `||`, CASE, a UNION of two different columns) is
redacted whole. `COUNT(col)`, `COUNT(DISTINCT col)`, `COUNT(*)`, `ROW_NUMBER` and `RANK` are clean. COUNT over a
computed argument is not, because it counts the matches of a condition.

**Predicate rules.** Masked columns may not appear, directly or through any expression, in WHERE, HAVING,
JOIN ON/USING, ORDER BY, window PARTITION/ORDER, or GROUP BY on a fragment of the value. A column can opt out
(`allowPredicates: true`) when the policy owner accepts that trade-off. The FsCheck property
"any filter that depends on a masked column is rejected" checks this on generated predicates.

**Value scanning.** Every remaining cell is scanned by in-process recognisers built for Turkish data:

- TCKN with both check digits;
- TR IBAN with mod-97;
- Turkish mobile and landline formats, including +90, 0090, 0 and 850;
- e-mail addresses;
- Luhn-valid card numbers with issuer prefixes, including TROY.

Numbers are scanned too, because a TCKN stored in a NUMBER column is still a TCKN. Free-text cells are also sent
to **Microsoft Presidio** (analyzer as a sidecar container). Cells are batched into one `/analyze` request per
20,000-character chunk, and Presidio's code-point offsets are mapped back to UTF-16 per cell. Overlapping
detections merge longest-first.

**Failure mode.** If Presidio is configured and unreachable, the call is refused (`MaskingUnavailable`).
`BuiltInOnly` degradation is opt-in and is flagged in both the response and the audit record.

**Injection heuristics.** Cells that read like instructions to a model are *flagged, not blocked*, in the
response warnings and the audit record. The tool description and every response also carry an "untrusted data"
notice, a light form of spotlighting.

## Consequences

- The laundering cases (ATK-35 to ATK-38) and the counting oracle are unit-tested. The FsCheck property
  "every output derived from a masked column is masked" holds on generated queries.
- Over-masking is possible and accepted. An ambiguous unqualified column resolves to the union of its
  candidates' lineage.
- Presidio's default model is English. On the synthetic notes it finds e-mails, cards and IBANs, but its PERSON
  recall on Turkish names is measured and reported in `docs/benchmarks.md`, not assumed. The built-in
  recognisers carry the Turkish identifiers. A Turkish spaCy/transformer model for Presidio is a next step.
- The injection heuristic catches obvious payloads only. The design does not depend on it: what a successfully
  injected agent can *obtain* is bounded by masking, the row cap and the row budget.

## Sources

- Microsoft Presidio, supported entities: <https://microsoft.github.io/presidio/supported_entities>
- Microsoft Presidio, Docker deployment and REST API: <https://microsoft.github.io/presidio/samples/docker>
- Presidio analyzer image tags (pinned 2.2.362): <https://mcr.microsoft.com/v2/presidio-analyzer/tags/list>
- Hines et al., "Defending Against Indirect Prompt Injection Attacks With Spotlighting" (2024): <https://arxiv.org/abs/2403.14720>
- OWASP Top 10 for LLM Applications 2025, LLM02 sensitive information disclosure: <https://genai.owasp.org/llm-top-10/>
