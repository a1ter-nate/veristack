<!-- featlock:start -->
## FeatLock Feature & Invariant Guard Rules
- Before implementing any new capability, run `featlock query <topic>` and `featlock check-dup "<summary>"` so you do not duplicate an existing feature.
- On every change that adds or improves product behavior, automatically record it with `featlock record-new` or `featlock record-improvement` in `features/registry.sql`.
- NEVER delete an active feature, unlink its tests, or delete an active invariant without explicit human confirmation, an ADR reference, and `ALLOW_FEATURE_REMOVAL=1`.
<!-- featlock:end -->
