from pathlib import Path

from cwe_witness.path_discovery import infer_path_policy


def test_infers_a_unique_fixed_file_prefix(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text('int main(void) { fopen("safe/records.txt", "r"); }')

    policy, origin, evidence = infer_path_policy([str(source)])

    assert policy.allowed_root == "safe"
    assert origin == "source_inference"
    assert evidence


def test_uses_working_directory_when_source_is_ambiguous(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text(
        'int main(void) { fopen("one/a.txt", "r"); fopen("two/b.txt", "r"); }'
    )

    policy, origin, _ = infer_path_policy([str(source)])

    assert policy.allowed_root == "/work"
    assert policy.boundary_source == "working_directory_assumption"
    assert origin == "working_directory_assumption"


def test_infers_simple_macro_used_by_file_operation(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text('#define RECORD_PATH "records/item.txt"\nint main(void) { fopen(RECORD_PATH, "r"); }')

    policy, origin, _ = infer_path_policy([str(source)])

    assert policy.allowed_root == "records"
    assert origin == "source_inference"
