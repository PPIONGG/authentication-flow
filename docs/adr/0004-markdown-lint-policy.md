# Markdown lint policy

We lint every `*.md` with `markdownlint-cli2`, configured by a root
`.markdownlint-cli2.jsonc` and pinned via the root `package.json`. We keep the
default ruleset with three deliberate deviations: **MD013** (line-length) and
**MD036** (no-emphasis-as-heading) are OFF, and **MD010** (no-hard-tabs) is
relaxed inside code blocks.

The reasons are specific to this repo. The docs are bilingual, and Thai has no
inter-word spaces to wrap on, so a hard column cap (MD013) would force unnatural
breaks and mean perpetual reflow churn on long-form prose and embedded code
samples — these are meant to be read with editor soft-wrap, not at 80 columns.
The writing-plans format uses bold one-line labels (`**Files**`, `**Step 1:
...**`) as structure inside task lists; MD036 would push those to real headings,
bloating the table of contents and breaking the format. Code samples legitimately
contain tabs (a Caddyfile today, a Makefile or Go sample tomorrow), so MD010 is
scoped to prose only and leaves code blocks untouched.

Every other default rule stays ON. They catch real cruft, not style — enabling
them surfaced three stray agent-preamble lines at the top of plan docs (MD041)
and a bare URL in the handoff (MD034), which we removed rather than silenced. The
linter version is pinned (`markdownlint-cli2` 0.22.1 / markdownlint 0.40.0) so
the editor extension and the CLI agree, and a newer engine's new rules (e.g.
MD060, which appeared between versions) cannot silently reintroduce "errors" we
never wrote.

We considered two alternatives. **Strict** — keep all defaults and rewrite all 14
docs (hard-wrap ~784 lines including Thai, convert 53 labels to headings) — was
rejected as high-churn and hostile to both the bilingual prose and the plan-doc
format. **Balanced** — keep a 100/120 line cap that exempts code and tables and
convert the pseudo-headings — was rejected because it still mandates reflowing
long prose and changes the plan format for little gain.

**Trade-off:** disabling MD013 leaves no automated guard against genuinely
runaway prose lines, and re-enabling it later means reflowing every long line at
once. We accept that — readability of bilingual long-form docs outweighs a column
rule that fights the language. CI enforcement is deferred per `ROADMAP.md` §9;
for now the policy lives in the editor and `npm run lint:md`.
