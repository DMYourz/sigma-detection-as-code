"""Unit tests for the offline Sigma matcher engine."""
from sigmatools.matcher import evaluate


def fires(detection, event):
    return evaluate(detection, event)


def test_endswith_and_contains_list():
    det = {
        "selection": {
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": [" -enc ", " -encodedcommand "],
        },
        "condition": "selection",
    }
    assert fires(det, {"Image": "C:\\Win\\powershell.exe", "CommandLine": "powershell -enc ABC"})
    assert not fires(det, {"Image": "C:\\Win\\powershell.exe", "CommandLine": "powershell -File a.ps1"})
    assert not fires(det, {"Image": "C:\\Win\\cmd.exe", "CommandLine": "cmd -enc ABC"})


def test_case_insensitive_by_default():
    det = {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"}
    assert fires(det, {"Image": "C:\\Win\\POWERSHELL.EXE"})


def test_contains_all_modifier():
    det = {"selection": {"CommandLine|contains|all": ["process", "call", "create"]}, "condition": "selection"}
    assert fires(det, {"CommandLine": "wmic process call create calc.exe"})
    assert not fires(det, {"CommandLine": "wmic process list"})


def test_and_not_filter():
    det = {
        "selection": {"TargetImage|endswith": "\\lsass.exe"},
        "filter": {"SourceImage|endswith": ["\\wininit.exe", "\\msmpeng.exe"]},
        "condition": "selection and not filter",
    }
    assert fires(det, {"TargetImage": "C:\\Win\\lsass.exe", "SourceImage": "C:\\tmp\\mimikatz.exe"})
    assert not fires(det, {"TargetImage": "C:\\Win\\lsass.exe", "SourceImage": "C:\\Win\\wininit.exe"})


def test_one_of_pattern():
    det = {
        "selection_certutil": {"Image|endswith": "\\certutil.exe"},
        "selection_bits": {"Image|endswith": "\\bitsadmin.exe"},
        "condition": "1 of selection_*",
    }
    assert fires(det, {"Image": "C:\\Win\\certutil.exe"})
    assert fires(det, {"Image": "C:\\Win\\bitsadmin.exe"})
    assert not fires(det, {"Image": "C:\\Win\\cmd.exe"})


def test_all_of_them():
    det = {"sel1": {"A": "1"}, "sel2": {"B": "2"}, "condition": "all of them"}
    assert fires(det, {"A": "1", "B": "2"})
    assert not fires(det, {"A": "1"})


def test_keywords():
    det = {"keywords": ["mimikatz", "sekurlsa::logonpasswords"], "condition": "keywords"}
    assert fires(det, {"CommandLine": "run mimikatz now"})
    assert not fires(det, {"CommandLine": "run calc"})


def test_list_of_maps_is_or():
    det = {
        "selection": [
            {"Image|endswith": "\\mshta.exe"},
            {"Image|endswith": "\\wscript.exe"},
        ],
        "condition": "selection",
    }
    assert fires(det, {"Image": "C:\\Win\\mshta.exe"})
    assert fires(det, {"Image": "C:\\Win\\wscript.exe"})
    assert not fires(det, {"Image": "C:\\Win\\cmd.exe"})


def test_wildcards():
    det = {"selection": {"Image": "*\\evil?.exe"}, "condition": "selection"}
    assert fires(det, {"Image": "C:\\a\\evil1.exe"})
    assert not fires(det, {"Image": "C:\\a\\evilXX.exe"})  # ? = exactly one char


def test_regex_modifier():
    det = {"selection": {"CommandLine|re": "-enc(odedcommand)?\\s"}, "condition": "selection"}
    assert fires(det, {"CommandLine": "powershell -enc ABC"})
    assert not fires(det, {"CommandLine": "powershell -file a.ps1"})


def test_windash_modifier():
    det = {"selection": {"CommandLine|windash|contains": "-encodedcommand"}, "condition": "selection"}
    assert fires(det, {"CommandLine": "powershell /encodedcommand ABC"})
    assert fires(det, {"CommandLine": "powershell -encodedcommand ABC"})
    assert not fires(det, {"CommandLine": "powershell -file a.ps1"})


def test_base64_modifier():
    det = {"selection": {"CommandLine|base64|contains": "whoami"}, "condition": "selection"}
    assert fires(det, {"CommandLine": "echo d2hvYW1p | something"})  # base64('whoami')
    assert not fires(det, {"CommandLine": "echo hello"})


def test_null_and_absent():
    det = {"selection": {"User": None}, "condition": "selection"}
    assert fires(det, {"Image": "x"})            # field absent -> null matches
    assert not fires(det, {"User": "SYSTEM"})    # present -> null does not match

    det2 = {"selection": {"CommandLine|contains": "x"}, "condition": "selection"}
    assert not fires(det2, {"Image": "x"})       # field absent -> contains fails
