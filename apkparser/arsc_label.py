"""Point-lookup for a single ARSC string resource (app label).

Avoids constructing the full Python ARSCParser object graph (every type-spec
and every resource entry), which dominates time on large ``resources.arsc``.
"""

from __future__ import annotations

import io
from struct import unpack

from axml.arsc.parser import (
    ARSCHeader,
    ARSCResTableEntry,
    ARSCResTablePackage,
    ARSCResType,
    PackageContext,
)
from axml.parser.stringblock import StringBlock
from axml.utils.constants import (
    RES_STRING_POOL_TYPE,
    RES_TABLE_PACKAGE_TYPE,
    RES_TABLE_TYPE,
    RES_TABLE_TYPE_SPEC_TYPE,
    RES_TABLE_TYPE_TYPE,
    TYPE_REFERENCE,
    TYPE_STRING,
)
from axml.utils.formatters import format_value


def resolve_arsc_string(raw: bytes, res_id: int, *, _depth: int = 0) -> str | None:
    """Return the default-config string for ``res_id``, or ``None`` to fall back."""
    if _depth > 8 or not raw or res_id <= 0:
        return None
    pkg_id = (res_id >> 24) & 0xFF
    type_id = (res_id >> 16) & 0xFF
    entry_idx = res_id & 0xFFFF
    try:
        buff = io.BufferedReader(io.BytesIO(raw))
        header = ARSCHeader(buff, expected_type=RES_TABLE_TYPE)
        buff.seek(header.start + header.header_size)
        stringpool_main = None
        while buff.tell() <= header.end - ARSCHeader.SIZE:
            res_header = ARSCHeader(buff)
            if res_header.end > header.end:
                break
            if res_header.type == RES_STRING_POOL_TYPE:
                if stringpool_main is None:
                    stringpool_main = StringBlock(buff, res_header.size)
                buff.seek(res_header.end)
                continue
            if res_header.type != RES_TABLE_PACKAGE_TYPE:
                buff.seek(res_header.end)
                continue

            current_package = ARSCResTablePackage(buff, res_header)
            if current_package.id != pkg_id:
                buff.seek(res_header.end)
                continue

            buff.seek(current_package.header.start + current_package.typeStrings)
            type_sp_header = ARSCHeader(buff, expected_type=RES_STRING_POOL_TYPE)
            table_strings = StringBlock(buff, type_sp_header.size)
            buff.seek(current_package.header.start + current_package.keyStrings)
            key_sp_header = ARSCHeader(buff, expected_type=RES_STRING_POOL_TYPE)
            key_strings = StringBlock(buff, key_sp_header.size)
            pc = PackageContext(
                current_package, stringpool_main, table_strings, key_strings
            )

            next_idx = (
                res_header.start
                + res_header.header_size
                + type_sp_header.size
                + key_sp_header.size
            )
            buff.seek(next_idx)

            found = None
            while buff.tell() <= res_header.end - ARSCHeader.SIZE:
                pkg_chunk = ARSCHeader(buff)
                if pkg_chunk.start + pkg_chunk.size > res_header.end:
                    break
                if pkg_chunk.type == RES_TABLE_TYPE_TYPE:
                    start_of_chunk = buff.tell() - 8
                    a_res_type = ARSCResType(buff, pc)
                    if a_res_type.id == type_id:
                        found = _entry_string(
                            buff,
                            a_res_type,
                            start_of_chunk,
                            pkg_chunk,
                            entry_idx,
                            stringpool_main,
                        )
                        if found is not None:
                            break
                buff.seek(pkg_chunk.end)
            if found is None:
                return None
            if isinstance(found, tuple) and found[0] == "ref":
                return resolve_arsc_string(raw, found[1], _depth=_depth + 1)
            return found
    except Exception:
        return None
    return None


def _entry_string(
    buff,
    a_res_type,
    start_of_chunk,
    pkg_chunk,
    entry_idx,
    stringpool_main,
):
    FLAG_OFFSET16 = 0x02
    NO_ENTRY_16 = 0xFFFF
    NO_ENTRY_32 = 0xFFFFFFFF
    if entry_idx >= a_res_type.entryCount:
        return None
    expected_end = start_of_chunk + pkg_chunk.size
    expected_entries_start = start_of_chunk + a_res_type.entriesStart
    offset = None
    if a_res_type.flags & FLAG_OFFSET16:
        buff.seek(buff.tell() + entry_idx * 2)
        off16 = unpack("<H", buff.read(2))[0]
        if off16 != NO_ENTRY_16:
            offset = off16 * 4
    else:
        buff.seek(buff.tell() + entry_idx * 4)
        off32 = unpack("<I", buff.read(4))[0]
        if off32 != NO_ENTRY_32:
            offset = off32
    if offset is None:
        return None
    ate = ARSCResTableEntry(
        buff,
        expected_entries_start + offset,
        expected_end,
        a_res_type.mResId & 0xFFFF0000 | entry_idx,
        a_res_type.parent,
    )
    if ate.is_complex():
        return None
    if ate.is_compact():
        data_type = ate.datatype
        data = ate.data
    else:
        data_type = ate.key.data_type
        data = ate.key.data
    if data_type in (TYPE_REFERENCE,):
        return ("ref", data)
    if data_type == TYPE_STRING and stringpool_main is not None:
        return stringpool_main.getString(data)
    if stringpool_main is None:
        return None
    return format_value(data_type, data, stringpool_main.getString)
