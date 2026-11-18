# Local Markdown issue tracker

- Keep each feature under `.scratch/<feature-slug>/` with its spec in `spec.md`.
- Store one implementation ticket per file in `issues/<NN>-<slug>.md`, numbered from `01`. Record prerequisite tickets on the `Blocked by:` line.
- Record triage state on a `Status:` line near the top of each ticket. Use the values in `triage-labels.md`.
- Append discussion under `## Comments`.
- When a skill publishes work, create the appropriate file in the feature directory. When fetching work, read the referenced path or resolve the ticket number in the current feature.

## Wayfinding

- Keep the map at `.scratch/<effort>/map.md` and decision tickets in its `issues/` directory.
- Give each decision ticket a `Type:` of `research`, `prototype`, `grilling`, or `task`. Use `Blocked by: NN, NN` for prerequisites.
- Pick the lowest-numbered unclaimed ticket whose prerequisites are all `resolved`. Set `Status: claimed` before starting.
- To resolve a ticket, add `## Answer`, set `Status: resolved`, and link the answer from the map’s Decisions-so-far section.
