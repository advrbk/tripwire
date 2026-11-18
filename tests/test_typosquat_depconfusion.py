"""typosquat (look-alike names) and depconfusion (absurd versions on unknown names)."""

import pytest
from helpers import npm_pkg, py_pkg

from tripwire.analyzers.depconfusion import DepConfusionAnalyzer, is_calendar_major, major_version
from tripwire.analyzers.typosquat import TyposquatAnalyzer, find_squat_target, normalize, osa_distance, popular

T = TyposquatAnalyzer()
D = DepConfusionAnalyzer()


# ------------------------------------------------------------------ typosquat

@pytest.mark.parametrize("a,b,d", [
    ("requests", "requests", 0), ("reqeusts", "requests", 1), ("requests", "request", 1),
    ("requestss", "requests", 1), ("rqeuests", "requests", 1), ("abc", "xyz", 3), ("short", "muchlongername", 3),
])
def test_osa_distance(a, b, d):
    assert osa_distance(a, b) == d


def test_pep503_normalisation():
    assert normalize("Python_DateUtil", "pypi") == "python-dateutil"
    assert normalize("Some.Pkg", "pypi") == "some-pkg"
    assert normalize("Some.Pkg", "npm") == "some.pkg"


def test_popular_lists_load_and_dedupe():
    assert "requests" in popular("pypi") and "lodash" in popular("npm")
    assert len(popular("pypi")) == len(set(popular("pypi")))


@pytest.mark.parametrize("name,eco,target,phrase", [
    ("reqeusts", "pypi", "requests", "swapped"),
    ("requestss", "pypi", "requests", "doubled"),
    ("reqests", "pypi", "requests", "left out"),
    ("nunpy", "pypi", "numpy", "keyboard neighbour"),
    ("djang0", "pypi", "django", "look-alike"),
    ("python-dateutils", "pypi", "python-dateutil", "extra letter"),
    ("crossenv", "npm", "cross-env", "separators"),
    ("lodahs", "npm", "lodash", "swapped"),
    ("expresss", "npm", "express", "doubled"),
    ("requests-py", "pypi", "requests", "'-py' added"),
    ("node-lodash", "npm", "lodash", "'node-' added"),
])
def test_lookalikes(name, eco, target, phrase):
    hit = find_squat_target(name, eco)
    assert hit is not None
    assert hit[0] == target and phrase in hit[1]


def test_glyph_scores_higher_than_affix():
    assert find_squat_target("djang0", "pypi")[2] > find_squat_target("requests-py", "pypi")[2]


@pytest.mark.parametrize("name,eco", [
    ("requests", "pypi"),            # the real thing
    ("Requests", "pypi"),            # same after normalisation
    ("requests-toolbelt", "pypi"),   # popular itself
    ("flask-login", "pypi"),         # extension naming, not an affix in the list
    ("numpyro", "pypi"),             # two edits from a short name: not checked
    ("tinymath", "pypi"),
    ("left-pad", "npm"),
    ("@acme/lodash", "npm"),         # scoped names are compared only with scoped names
])
def test_not_lookalikes(name, eco):
    assert find_squat_target(name, eco) is None


def test_analyzer_output():
    ev = T.analyze(py_pkg({"p/__init__.py": ""}, name="reqeusts"))
    assert len(ev) == 1 and ev[0].rule == "name_lookalike"
    assert ev[0].snippet == "reqeusts ~ requests"
    assert T.analyze(py_pkg({"p/__init__.py": ""}, name="requests")) == []


def test_known_weakness_port_naming():
    # "<popular>-js" ports are common and legitimate; the affix rule still scores them.
    hit = find_squat_target("yaml-js", "npm")
    assert hit is not None and hit[2] == 0.35


# --------------------------------------------------------------- depconfusion

@pytest.mark.parametrize("version,major", [("1.2.3", 1), ("v100.0", 100), ("99", 99), ("abc", None), ("", None)])
def test_major_version(version, major):
    assert major_version(version) == major


@pytest.mark.parametrize("major,cal", [(2024, True), (1999, True), (20241105, True), (202411, True),
                                        (99, False), (9000, False), (20241399, False), (999999, False)])
def test_calendar_detection(major, cal):
    assert is_calendar_major(major) is cal


def test_absurd_version_on_unknown_name():
    ev = D.analyze(npm_pkg(name="acme-billing", version="99.0.0", description="billing helpers"))
    assert [e.rule for e in ev] == ["absurd_version"] and ev[0].weight == 0.45


def test_huge_version_weighs_more():
    ev = D.analyze(npm_pkg(name="acme-billing", version="9000.0.0", description="x"))
    assert ev[0].weight == 0.55


def test_internal_name_and_empty_metadata_add_context():
    pkg = py_pkg({"x/__init__.py": ""}, name="acme-internal-auth", version="99.0.0")
    rules = {e.rule for e in D.analyze(pkg)}
    assert rules == {"absurd_version", "internal_sounding_name", "empty_metadata"}


@pytest.mark.parametrize("name,version", [
    ("acme-billing", "98.9.9"),       # high but under the line
    ("tzrules", "2024.11.5"),         # calendar versioning
    ("daily-rates", "20241105.0.0"),  # date stamp
    ("lodash", "100.0.0"),            # popular names are exempt
    ("acme-internal-tools", "1.4.2"),  # internal-sounding but a normal version
])
def test_depconfusion_negatives(name, version):
    assert D.analyze(npm_pkg(name=name, version=version)) == []
