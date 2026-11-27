import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bench"))

import fakefeed  # noqa: E402

INSTALLED = ["base-files", "kmod-foo", "alpha", "libbeta5", "gamma", "meta", "stamp"]


@pytest.fixture(scope="session")
def signer():
    return fakefeed.Signer()


@pytest.fixture(scope="session")
def release_root(tmp_path_factory, signer):
    root = tmp_path_factory.mktemp("mirror") / "releases"
    fakefeed.make_release(root, signer)
    return root


@pytest.fixture(scope="session")
def ref(release_root, signer, tmp_path_factory):
    return fakefeed.reference(release_root, signer, tmp_path_factory.mktemp("cache"))


@pytest.fixture()
def rootfs(tmp_path):
    return fakefeed.make_rootfs(tmp_path / "rootfs", INSTALLED)


@pytest.fixture()
def truth():
    return fakefeed.claims(INSTALLED)
