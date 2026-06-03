"""Tests for the comment/string-stripping source model and function parsing."""
from __future__ import annotations

from auditor.engine import audit_source
from auditor.source import SoliditySource, strip_comments_and_strings
from tests.conftest import detectors_for


def test_strip_preserves_line_count():
    src = "a\n// comment\n/* multi\nline */\nb\n"
    cleaned = strip_comments_and_strings(src)
    assert cleaned.count("\n") == src.count("\n")


def test_keyword_in_comment_does_not_fire():
    src = """
    pragma solidity 0.8.24;
    contract C {
        // this function uses tx.origin == owner historically
        function f() external pure returns (uint) { return 1; }
    }
    """
    result = audit_source(src, path="C.sol")
    assert "tx-origin-auth" not in detectors_for(result)


def test_keyword_in_string_does_not_fire():
    src = '''
    pragma solidity 0.8.24;
    contract C {
        function note() external pure returns (string memory) {
            return "selfdestruct is dangerous";
        }
    }
    '''
    result = audit_source(src, path="C.sol")
    assert "unprotected-selfdestruct" not in detectors_for(result)


def test_function_extraction_basic():
    src = """
    pragma solidity 0.8.24;
    contract C {
        function a() public {}
        function b(uint x) external payable onlyOwner returns (uint) { return x; }
        modifier onlyOwner() { _; }
    }
    """
    s = SoliditySource(src, path="C.sol")
    names = {f.name for f in s.functions}
    assert {"a", "b", "onlyOwner"} <= names
    b = next(f for f in s.functions if f.name == "b")
    assert b.visibility == "external"
    assert b.is_payable
    assert "onlyOwner" in b.modifiers


def test_nested_braces_body_extraction():
    src = """
    pragma solidity 0.8.24;
    contract C {
        function f() external {
            if (true) { while (false) { } }
        }
        function g() external {}
    }
    """
    s = SoliditySource(src, path="C.sol")
    f = next(fn for fn in s.functions if fn.name == "f")
    # The body must include the nested blocks but stop before g().
    assert "while" in f.body
    assert "function g" not in f.body


def test_line_numbers_are_one_based_and_accurate():
    src = "pragma solidity 0.8.24;\ncontract C {\n    function f() external {}\n}\n"
    s = SoliditySource(src, path="C.sol")
    f = next(fn for fn in s.functions if fn.name == "f")
    assert f.header_line == 3
