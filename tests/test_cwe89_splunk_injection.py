"""
PoC test for CWE-89: SPL Injection via keyword parameter in _format_splunk_keyword.

The _format_splunk_keyword method uses backslash escaping (\\") to escape double
quotes, but SPL uses quote-doubling ("") for escaping within quoted strings.
Backslash has no special escape meaning in SPL quoted strings, so a keyword
containing a double quote can break out of the quoted context and inject
arbitrary SPL commands.

This test file extracts the relevant functions directly so it can run without
the full Django/Splunk/ELK environment.
"""

import sys
import re


# ---------- Extract the vulnerable functions from tools.py ----------
# We copy the exact logic so the test validates the actual algorithm.
# After the fix, we re-import from the real module (via mock shim).


def _format_splunk_keyword_ORIGINAL(keyword: str) -> str:
    """Original (vulnerable) implementation."""
    if re.fullmatch(r"[A-Za-z0-9._:@/\\-]+", keyword):
        return keyword
    escaped_keyword = keyword.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped_keyword}"'


def _normalize_keywords(keyword_input):
    if isinstance(keyword_input, str):
        return [keyword_input]
    return keyword_input


def _build_splunk_keyword_clause_with(format_fn, keyword_input):
    keywords = _normalize_keywords(keyword_input)
    return " AND ".join(format_fn(keyword) for keyword in keywords)


# ---------- SPL safety checkers ----------

def _spl_would_inject(formatted: str) -> bool:
    """
    Check if a formatted SPL keyword token would allow injection.
    A safe token is either:
      1. Unquoted simple alphanumeric: [A-Za-z0-9._:@/\\-]+
      2. Double-quoted with all internal quotes doubled ("")
    """
    if re.fullmatch(r"[A-Za-z0-9._:@/\\-]+", formatted):
        return False

    if formatted.startswith('"') and formatted.endswith('"'):
        inner = formatted[1:-1]
        sanitized = inner.replace('""', '')
        if '"' in sanitized:
            return True
        return False

    return True


def _spl_clause_would_inject(clause: str) -> bool:
    """
    Walk through the clause tracking SPL quote context.
    A pipe (|) outside of a properly-quoted string means injection.
    """
    in_quote = False
    i = 0
    while i < len(clause):
        c = clause[i]
        if c == '"':
            if in_quote:
                # Check for doubled quote (escaped)
                if i + 1 < len(clause) and clause[i + 1] == '"':
                    i += 2
                    continue
                else:
                    in_quote = False
            else:
                in_quote = True
        elif c == '|' and not in_quote:
            return True
        i += 1
    return False


# ---------- Now try to import the REAL function after fix ----------

def _get_real_format_fn():
    """Try to import the real _format_splunk_keyword from the codebase."""
    import importlib
    import unittest.mock as mock

    # We need to mock out the problematic imports
    modules_to_mock = [
        'PLUGINS.ELK.CONFIG',
        'PLUGINS.ELK.client',
        'PLUGINS.Splunk.client',
        'PLUGINS.SIEM.registry',
        'splunklib',
        'splunklib.results',
        'elasticsearch',
    ]

    saved = {}
    for mod_name in modules_to_mock:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = mock.MagicMock()
            saved[mod_name] = True

    try:
        # Force re-import
        if 'PLUGINS.SIEM.tools' in sys.modules:
            del sys.modules['PLUGINS.SIEM.tools']
        if 'PLUGINS.SIEM.models' in sys.modules:
            del sys.modules['PLUGINS.SIEM.models']

        WORKTREE = "/Users/sebastion/projects/audits/FunnyWolf-agentic-soc-platform-worktrees/cwe89-tools-splunk-61f6"
        if WORKTREE not in sys.path:
            sys.path.insert(0, WORKTREE)

        from PLUGINS.SIEM.tools import SIEMToolKit
        return SIEMToolKit._format_splunk_keyword, SIEMToolKit._build_splunk_keyword_clause
    except Exception as e:
        print(f"  WARNING: Could not import real module ({e}), using extracted copy")
        return None, None


# ---------- Test class ----------

class TestSPLInjection:

    def __init__(self, format_fn, clause_fn):
        self.format_fn = format_fn
        self.clause_fn = clause_fn

    def test_basic_injection_via_double_quote(self):
        """A keyword with embedded double quote should not allow SPL injection."""
        keyword = 'foo" | delete index=* | search "bar'
        formatted = self.format_fn(keyword)
        assert not _spl_would_inject(formatted), (
            f"SPL injection possible! Formatted keyword: {formatted!r}\n"
            f"A double-quote in the keyword broke out of the quoted context."
        )

    def test_clause_injection_via_double_quote(self):
        """The full clause built from a malicious keyword should not contain unquoted pipes."""
        keyword = 'foo" | delete index=* | search "bar'
        clause = self.clause_fn(keyword)
        assert not _spl_clause_would_inject(clause), (
            f"SPL injection in clause! Clause: {clause!r}\n"
            f"Pipe operator found outside quoted context."
        )

    def test_backslash_quote_combo(self):
        """Backslash followed by double quote should still be safe."""
        keyword = 'test\\" | stats count'
        formatted = self.format_fn(keyword)
        assert not _spl_would_inject(formatted), (
            f"SPL injection via backslash-quote combo! Formatted: {formatted!r}"
        )

    def test_clause_backslash_quote_combo(self):
        keyword = 'test\\" | stats count'
        clause = self.clause_fn(keyword)
        assert not _spl_clause_would_inject(clause), (
            f"SPL injection in clause! Clause: {clause!r}"
        )

    def test_multiple_keywords_injection(self):
        keywords = ["safe_keyword", 'evil" | delete index=*']
        clause = self.clause_fn(keywords)
        assert not _spl_clause_would_inject(clause), (
            f"SPL injection in multi-keyword clause! Clause: {clause!r}"
        )

    def test_safe_keyword_unchanged(self):
        keyword = "192.168.1.100"
        formatted = self.format_fn(keyword)
        assert formatted == keyword, f"Safe keyword was modified: {formatted!r}"

    def test_safe_keyword_with_special_chars(self):
        keyword = "user@domain.com"
        formatted = self.format_fn(keyword)
        assert formatted == keyword

    def test_keyword_needing_quotes(self):
        keyword = "hello world"
        formatted = self.format_fn(keyword)
        assert formatted == '"hello world"'
        assert not _spl_would_inject(formatted)

    def test_keyword_with_only_quotes(self):
        keyword = '""'
        formatted = self.format_fn(keyword)
        assert not _spl_would_inject(formatted), (
            f"SPL injection with quotes-only keyword! Formatted: {formatted!r}"
        )

    def test_spl_pipe_injection_in_search_query(self):
        keyword = 'foo" | delete index=* | search "bar'
        clause = self.clause_fn(keyword)
        search_query = f'search index="*" ({clause})'
        assert not _spl_clause_would_inject(search_query), (
            f"SPL injection in full search query! Query: {search_query!r}"
        )

    def test_single_quote_keyword(self):
        """A keyword that is a single double quote."""
        keyword = '"'
        formatted = self.format_fn(keyword)
        assert not _spl_would_inject(formatted), (
            f"SPL injection with single-quote keyword! Formatted: {formatted!r}"
        )

    def test_pipe_in_keyword(self):
        """A keyword containing just a pipe should be safely quoted."""
        keyword = "foo | bar"
        formatted = self.format_fn(keyword)
        assert not _spl_would_inject(formatted)
        clause = self.clause_fn(keyword)
        assert not _spl_clause_would_inject(clause)


def run_tests(format_fn, clause_fn, label=""):
    test_obj = TestSPLInjection(format_fn, clause_fn)
    tests = [m for m in dir(test_obj) if m.startswith('test_')]
    failures = []
    passes = []

    if label:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")

    for test_name in sorted(tests):
        test_method = getattr(test_obj, test_name)
        try:
            test_method()
            passes.append(test_name)
            print(f"  PASS: {test_name}")
        except AssertionError as e:
            failures.append((test_name, str(e)))
            print(f"  FAIL: {test_name}")
            for line in str(e).split('\n'):
                print(f"        {line}")
        except Exception as e:
            failures.append((test_name, str(e)))
            print(f"  ERROR: {test_name}: {e}")

    print(f"\n  {len(passes)} passed, {len(failures)} failed out of {len(tests)} tests")
    return len(failures)


if __name__ == "__main__":
    # First, demonstrate the vulnerability with the ORIGINAL code
    original_clause_fn = lambda ki: _build_splunk_keyword_clause_with(_format_splunk_keyword_ORIGINAL, ki)
    orig_failures = run_tests(
        _format_splunk_keyword_ORIGINAL,
        original_clause_fn,
        "ORIGINAL (vulnerable) implementation"
    )

    # Now try the real (potentially fixed) implementation
    real_format_fn, real_clause_fn = _get_real_format_fn()
    if real_format_fn:
        real_failures = run_tests(
            real_format_fn,
            real_clause_fn,
            "REAL implementation from tools.py"
        )
    else:
        real_failures = orig_failures  # Fallback

    # Exit with failure if the real implementation has issues
    if real_format_fn:
        sys.exit(real_failures)
    else:
        sys.exit(orig_failures)
