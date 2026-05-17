# tpolicy_checker

A policy inspector for Windows trustlet binaries.

Trustlets are isolated user-mode processes running in VTL1. Their security policy are embedded directly in the PE from an exported `__ImagePolicyMetadata` symbol. `tpolicy_checker` parses that structure and prints a human-readable summary.

## Output

```json
{
  "Name": "lsaiso.exe"
  "Trustlet ID": 1,
  "Version": 1,
  "Policies": {
    "Allow Debugging":            "No",
    "Allow ETW":                  "Yes",
    "Allow Encrypted Crash Dump": "Yes",
    "CrashDumpKey":               "5253...",
    "CrashDumpKeyGuid":           "{A1B2C3D4-...}",
  },
}
```

## Requirements

- Python 3.10+
- [pefile](https://github.com/erocarrera/pefile)

## Setup

```bash
pip install pefile
```

## Usage

```
python tpolicy_checker.py -f <binary> [-o <output.json>]
```

| Argument | Description |
|---|---|
| `-f`, `--file` | Path to the trustlet PE binary |
| `-o`, `--output` | Write JSON output to this file instead of stdout |

### Examples

```bash
# Print to stdout
python tpolicy_checker.py -f lsaiso.exe

# Save to file
python tpolicy_checker.py -f lsaiso.exe -o lsaiso_policy.json
```
