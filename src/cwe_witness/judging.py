from .models import Decision, Observation, PredicateResult, Profile, Run


def judge(profile: Profile, run: Run, observations: list[Observation]) -> Decision:
    if run.timeout or run.output_limited:
        return Decision(status="ERROR", reason_code="TIMEOUT" if run.timeout else "OUTPUT_LIMIT")
    candidates = [item for item in observations if item.kind == profile.mechanism]
    candidates = candidates or observations

    def checks_for(item: Observation | None) -> dict[str, bool]:
        return {
            "valid_program_execution": (
                not run.timeout
                and not run.output_limited
                and (run.signal is None or bool(item and item.complete))
            ),
            "complete_runtime_report": bool(item and item.complete),
            "target_mechanism_observed": bool(item and item.kind == profile.mechanism),
            "target_code_attributed": bool(item and item.location),
            "access_direction_matches": bool(item and item.operation == profile.operation),
            "object_boundary_exceeded": bool(item and item.bounds_associated),
            "allocation_release_access_associated": bool(
                item
                and item.object_associated
                and item.allocation_location
                and item.release_location
            ),
            "resource_still_open_at_exit": bool(
                item
                and (
                    (item.kind == "posix_fd_leak" and item.descriptor is not None)
                    or item.kind == "custom_resource_leak"
                )
                and item.complete
            ),
            "path_outside_allowed": bool(item and item.path_outside_allowed),
            "path_access_succeeded": bool(item and item.path_access_succeeded),
            "copy_operation_observed": bool(item and item.copy_operation),
        }

    # Score each candidate once; keep the winner's checks to avoid recomputing.
    observation: Observation | None = None
    observation_checks: dict[str, bool] | None = None
    best_score = -1
    for item in candidates:
        item_checks = checks_for(item)
        score = sum(item_checks.get(name, False) for name in profile.required_predicates)
        if score > best_score:
            best_score = score
            observation = item
            observation_checks = item_checks
    if run.signal is not None and not (observation and observation.complete):
        return Decision(status="ERROR", reason_code="PROCESS_CRASH")
    checks = observation_checks if observation_checks is not None else checks_for(None)
    predicates = []
    for name in profile.required_predicates:
        passed = checks.get(name, False)
        contradicted = bool(
            observation
            and name in ("target_mechanism_observed", "access_direction_matches")
            and not passed
        )
        predicates.append(
            PredicateResult(
                predicate=name,
                status="SATISFIED" if passed else "CONTRADICTED" if contradicted else "UNKNOWN",
                evidence_ids=[observation.observation_id] if observation else [run.run_id],
                missing_requirements=[] if passed else [name],
                reason_code="EVIDENCE_SUPPORTS"
                if passed
                else "OTHER_ERROR_TRIGGERED_FIRST"
                if contradicted
                else "INSUFFICIENT_EVIDENCE",
            )
        )
    confirmed = all(p.status == "SATISFIED" for p in predicates)
    missing_predicates = {
        predicate.predicate for predicate in predicates if predicate.status != "SATISFIED"
    }
    return Decision(
        status="CONFIRMED" if confirmed else "NOT_CONFIRMED",
        reason_code="PROFILE_SATISFIED"
        if confirmed
        else "OTHER_ERROR_TRIGGERED_FIRST"
        if any(p.status == "CONTRADICTED" for p in predicates)
        else "NO_RUNTIME_EVIDENCE"
        if not observation
        else "SANITIZER_REPORT_INCOMPLETE"
        if not observation.complete
        else "OBJECT_BOUNDARY_NOT_PROVEN"
        if "object_boundary_exceeded" in missing_predicates
        else "INSUFFICIENT_RUNTIME_EVIDENCE",
        predicates=predicates,
    )
