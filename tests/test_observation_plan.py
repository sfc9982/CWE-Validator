import shutil
from pathlib import Path

import pytest

from cwe_witness.observation_plan import build_observation_plan
from cwe_witness.profiles import load_profile


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required for AST discovery")
def test_adaptive_plan_uses_source_candidates_and_honors_run_limit(tmp_path: Path) -> None:
    source = tmp_path / "candidate.c"
    source.write_text(
        "#include <stdlib.h>\n#include <unistd.h>\n"
        "int main(void) { int values[2] = {0}; int index = 1 + 1; "
        "values[index] = 3; free(NULL); close(0); return 0; }\n",
        encoding="utf-8",
    )
    profile = load_profile("c.oob-read@1.0.0")
    assert profile is not None

    plan = build_observation_plan([str(source)], profile, "adaptive", 1)

    assert plan.planned_observers[0] == profile.observer
    assert len(plan.planned_observers) <= 2
    assert {candidate.kind for candidate in plan.candidates} >= {
        "array_access", "arithmetic", "release", "resource_release"
    }
    assert all(candidate.execution_status == "unknown" for candidate in plan.candidates)


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required for AST discovery")
def test_explicit_mode_does_not_schedule_supplemental_observers(tmp_path: Path) -> None:
    source = tmp_path / "candidate.c"
    source.write_text("int main(void) { return 2 + 2; }\n", encoding="utf-8")
    profile = load_profile("c.oob-read@1.0.0")
    assert profile is not None

    plan = build_observation_plan([str(source)], profile, "explicit", 3)

    assert plan.planned_observers == [profile.observer]
