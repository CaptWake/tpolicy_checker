__author__ = "CaptWake"
__license__ = "MIT"
__version__ = "1.0.0"

import enum
import json
import struct
import argparse
from pathlib import Path
from dataclasses import field, dataclass

import pefile


# NOTE: The following enums are taken from windows ddk, may change in the future
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_image_policy_id
class ImagePolicyId(enum.IntEnum):
    NONE = 0
    Etw = 1
    Debug = 2
    CrashDump = 3
    CrashDumpKey = 4
    CrashDumpKeyGuid = 5
    ParentSd = 6
    ParentSdRev = 7
    Svn = 8
    DeviceId = 9
    Capability = 10
    ScenarioId = 11
    CapabilityOverridable = 12
    TrustletIdOverridable = 13


# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_image_policy_entry_type
class ImagePolicyEntryType(enum.IntEnum):
    NONE = 0
    Bool = 1
    Int8 = 2
    UInt8 = 3
    Int16 = 4
    UInt16 = 5
    Int32 = 6
    UInt32 = 7
    Int64 = 8
    UInt64 = 9
    AnsiString = 10
    UnicodeString = 11
    Override = 12


ENTRY_SIZE = 0x10


class PEReader:
    def __init__(self, path: Path) -> None:
        self._pe = pefile.PE(str(path), fast_load=False)
        self._image_base = self._pe.OPTIONAL_HEADER.ImageBase

    def close(self) -> None:
        self._pe.close()

    def __enter__(self) -> "PEReader":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _rva(self, va: int) -> int:
        return va - self._image_base

    def _data(self, va: int, size: int) -> bytes:
        return self._pe.get_data(self._rva(va), size)

    def read_u32(self, va: int) -> int:
        return struct.unpack_from("<I", self._data(va, 4))[0]

    def read_u64(self, va: int) -> int:
        return struct.unpack_from("<Q", self._data(va, 8))[0]

    def read_ansi(self, va: int, max_bytes: int = 512) -> str:
        raw = self._data(va, max_bytes)
        end = raw.find(b"\x00")
        return raw[:end].decode("utf-8", errors="replace")

    def read_unicode(self, va: int, max_bytes: int = 512) -> str:
        raw = self._data(va, max_bytes)
        i = 0
        while i < len(raw) - 1:
            if raw[i] == 0 and raw[i + 1] == 0:
                break
            i += 2
        return raw[:i].decode("utf-16-le", errors="replace")

    def find_export(self, name: str) -> int | None:
        if not hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            return None
        for sym in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name and sym.name.decode() == name:
                return self._image_base + sym.address
        return None


@dataclass
class PolicyEntry:
    name: str
    value: bool | int | str
    pretty_value: str

    @staticmethod
    def _decode(typ: ImagePolicyEntryType, raw: int, reader: PEReader) -> bool | int | str:
        match typ:
            case ImagePolicyEntryType.Bool:
                return bool(raw & 0xFF)
            case ImagePolicyEntryType.Int8 | ImagePolicyEntryType.UInt8:
                return raw & 0xFF
            case ImagePolicyEntryType.Int16 | ImagePolicyEntryType.UInt16:
                return raw & 0xFFFF
            case ImagePolicyEntryType.Int32 | ImagePolicyEntryType.UInt32:
                return raw & 0xFFFF_FFFF
            case ImagePolicyEntryType.Int64 | ImagePolicyEntryType.UInt64:
                return raw
            case ImagePolicyEntryType.AnsiString:
                return reader.read_ansi(raw)
            case ImagePolicyEntryType.UnicodeString:
                return reader.read_unicode(raw)
            case _:
                return raw

    @staticmethod
    def _format(pid: ImagePolicyId, value: bool | int | str) -> tuple[str, str]:
        """Return (display_name, pretty_value) for pid."""
        match pid:
            case ImagePolicyId.Etw:
                return "Allow ETW", "Yes" if value else "No"
            case ImagePolicyId.Debug:
                return "Allow Debugging", "Yes" if value else "No"
            case ImagePolicyId.CrashDump:
                return "Allow Encrypted Crash Dump", "Yes" if value else "No"
            case ImagePolicyId.CapabilityOverridable | ImagePolicyId.TrustletIdOverridable:
                return pid.name, "Yes" if value else "No"
            case ImagePolicyId.ParentSd:
                return "Parent SID", str(value)
            case ImagePolicyId.ParentSdRev:
                return "Verify Parent SID", "Yes" if value else "No"
            case ImagePolicyId.Capability:
                return pid.name, "Create Secure Section"
            case ImagePolicyId.ScenarioId:
                return pid.name, str(value)
            case _:
                return pid.name, str(value)

    @classmethod
    def from_raw(
        cls,
        pid: ImagePolicyId,
        typ: ImagePolicyEntryType,
        raw: int,
        reader: PEReader,
    ) -> "PolicyEntry":
        value = cls._decode(typ, raw, reader)
        name, pretty = cls._format(pid, value)
        return cls(name=name, value=value, pretty_value=pretty)


@dataclass
class PolicyMetadata:
    binary: str
    version: int
    trustlet_id: int
    entries: list[PolicyEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "Name": self.binary,
            "Trustlet ID": self.trustlet_id,
            "Version": self.version,
            "Policies": {e.name: e.pretty_value for e in sorted(self.entries, key=lambda e: e.name)},
        }


# ---------------------------------------------------------------------------
# main analysis
# ---------------------------------------------------------------------------

def analyze_policies(path: Path, output_path: Path | None) -> None:
    with PEReader(path) as reader:
        va = reader.find_export("__ImagePolicyMetadata")

        if va is None:
            print("[!] __ImagePolicyMetadata export not found, not a valid trustlet")
            return

        metadata = PolicyMetadata(
            binary=path.name,
            version=reader.read_u32(va),
            trustlet_id=reader.read_u32(va + 8),
        )

        entry = va + ENTRY_SIZE
        while True:
            typ = ImagePolicyEntryType(reader.read_u32(entry))
            pid = ImagePolicyId(reader.read_u32(entry + 4))
            raw = reader.read_u64(entry + 8)

            if typ == ImagePolicyEntryType.NONE and pid == ImagePolicyId.NONE:
                break

            metadata.entries.append(PolicyEntry.from_raw(pid, typ, raw, reader))
            entry += ENTRY_SIZE

    result = metadata.to_dict()

    if output_path:
        with output_path.open("w") as f:
            json.dump(result, f, indent=2)
        print(f"[*] Results saved to {output_path}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Trustlet Policy Checker")
    p.add_argument("-f", "--file", required=True, type=Path, help="Trustlet PE binary to analyze")
    p.add_argument("-o", "--output", default=None, type=Path, help="Write JSON output here instead of stdout")
    args = p.parse_args()

    if not args.file.is_file():
        p.error(f"Input file not found: {args.file}")

    analyze_policies(args.file, args.output)
