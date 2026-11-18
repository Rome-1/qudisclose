from vulnpkg import read_user_file, resolve_path


def test_reads_file_inside_root(tmp_path):
    (tmp_path / "hello.txt").write_bytes(b"hi")
    assert read_user_file(tmp_path, "hello.txt") == b"hi"


def test_resolve_nested(tmp_path):
    assert resolve_path(tmp_path, "a/b.txt") == tmp_path / "a" / "b.txt"
