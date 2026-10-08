"""Check authored Xcode metadata; this does NOT compile Swift or run XCTest."""
from __future__ import annotations

import json
from pathlib import Path
import plistlib
import re
import xml.etree.ElementTree as ET


def parse_openstep(text: str) -> dict:
    tokens = []
    pattern = re.compile(r'\s+|/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}()=;,]|[^\s{}()=;,]+', re.S)
    for match in pattern.finditer(text):
        token = match.group()
        if token.isspace() or token.startswith(("//", "/*")):
            continue
        tokens.append(json.loads(token) if token.startswith('"') else token)
    cursor = 0

    def take(expected=None):
        nonlocal cursor
        if cursor >= len(tokens):
            raise ValueError("unexpected end of project")
        token = tokens[cursor]
        cursor += 1
        if expected is not None and token != expected:
            raise ValueError(f"expected {expected!r}, got {token!r}")
        return token

    def value():
        if tokens[cursor] == "{":
            take("{")
            result = {}
            while tokens[cursor] != "}":
                key = take()
                take("=")
                if key in result:
                    raise ValueError(f"duplicate project key {key}")
                result[key] = value()
                take(";")
            take("}")
            return result
        if tokens[cursor] == "(":
            take("(")
            result = []
            while tokens[cursor] != ")":
                result.append(value())
                if tokens[cursor] == ",":
                    take(",")
                elif tokens[cursor] != ")":
                    raise ValueError("missing array separator")
            take(")")
            return result
        return take()

    result = value()
    if cursor != len(tokens) or not isinstance(result, dict):
        raise ValueError("unexpected project content")
    return result


def main():
    root = Path(__file__).resolve().parent
    project = parse_openstep((root / "XNETHome.xcodeproj/project.pbxproj").read_text(encoding="utf-8"))
    objects = project["objects"]
    object_id = re.compile(r"[A-F0-9]{24}")

    def check_references(value):
        if isinstance(value, dict):
            for item in value.values():
                check_references(item)
        elif isinstance(value, list):
            for item in value:
                check_references(item)
        elif object_id.fullmatch(value):
            if value not in objects:
                raise ValueError(f"missing Xcode object {value}")

    check_references(project)
    for obj in objects.values():
        if obj.get("isa") == "PBXFileReference" and obj["sourceTree"] == "SOURCE_ROOT":
            file = root / obj["path"]
            if not file.is_file() or not file.resolve().is_relative_to(root):
                raise ValueError(f"missing or escaping project file: {obj['path']}")
    source_phase = next(obj for obj in objects.values() if obj["isa"] == "PBXSourcesBuildPhase")
    compiled = {
        objects[objects[build]["fileRef"]]["path"]
        for build in source_phase["files"]
    }
    expected = {str(path.relative_to(root)).replace("\\", "/")
        for path in (root / "XNETHome").rglob("*.swift")}
    expected.add("AppleNativeContextBridge.swift")
    if compiled != expected:
        raise ValueError(f"app source phase mismatch: {compiled ^ expected}")
    scheme = ET.parse(root / "XNETHome.xcodeproj/xcshareddata/xcschemes/XNETHome.xcscheme")
    for reference in scheme.iter("BuildableReference"):
        if objects[reference.attrib["BlueprintIdentifier"]]["isa"] != "PBXNativeTarget":
            raise ValueError("scheme does not resolve to a target")
    privacy = plistlib.loads((root / "XNETHome/PrivacyInfo.xcprivacy").read_bytes())
    if privacy["NSPrivacyTracking"] is not False or privacy["NSPrivacyCollectedDataTypes"]:
        raise ValueError("unexpected privacy declaration")
    core = root / "XNETHome/SourceCore"
    for file in core.glob("*.swift"):
        imports = re.findall(r"^import (\w+)", file.read_text(encoding="utf-8"), re.M)
        if set(imports) - {"Foundation", "CryptoKit"}:
            raise ValueError(f"native SDK dependency in core: {file.name}")
    cases = re.findall(r"^\s+func (test\w+)\(",
        (root / "XNETHomeTests/SourceCoreTests.swift").read_text(encoding="utf-8"), re.M)
    print(json.dumps({"project_metadata_valid": True, "app_source_files": len(compiled),
        "authored_core_test_cases": len(cases), "swift_compiled": False,
        "xctest_executed": False, "physical_device_validated": False}, sort_keys=True))


if __name__ == "__main__":
    main()
