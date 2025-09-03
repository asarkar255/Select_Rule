# app_array.py (updated to handle SELECT * without INTO / implicit work area)
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Tuple, Set
import re
import json

app = FastAPI(title="ABAP SELECT* Analyzer/Remediator (Array JSON, ECC)")

# ---------- ECC-safe regex helpers ----------
# INTO clause is now OPTIONAL (handles implicit work area SELECT * ... .)
SELECT_STAR_RE = re.compile(
    r"""(?P<full>
            SELECT\s+(?:SINGLE\s+)?\*\s+FROM\s+(?P<table>\w+)
            (?P<middle>.*?)
            (?:
                (?:INTO\s+TABLE\s+(?P<into_tab>\w+)) |
                (?:INTO\s+(?P<into_wa>\w+))
            )?
            (?P<tail>.*?)
        )\.
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

LOOP_INTO_RE         = re.compile(r"LOOP\s+AT\s+(?P<itab>\w+)\s+INTO\s+(?P<wa>\w+)\s*\.", re.IGNORECASE)
LOOP_ASSIGNING_RE    = re.compile(r"LOOP\s+AT\s+(?P<itab>\w+)\s+ASSIGNING\s+<(?P<fs>\w+)>\s*\.", re.IGNORECASE)
READ_TABLE_INTO_RE   = re.compile(r"READ\s+TABLE\s+(?P<itab>\w+)[^\.]*\s+INTO\s+(?P<wa>\w+)\s*\.", re.IGNORECASE)
READ_TABLE_ASSIGNING_RE = re.compile(r"READ\s+TABLE\s+(?P<itab>\w+)[^\.]*\s+ASSIGNING\s+<(?P<fs>\w+)>\s*\.", re.IGNORECASE)
ASSIGN_FS_ITAB_RE    = re.compile(r"ASSIGN\s+(?P<itab>\w+)\s*\[[^\]]*\]\s+TO\s+<(?P<fs>\w+)>\s*\.", re.IGNORECASE)
HEADER_LINE_LOOP_RE  = re.compile(r"LOOP\s+AT\s+(?P<itab>\w+)\s*\.", re.IGNORECASE)

STRUCT_FIELD_RE_TMPL = r"(?<![A-Za-z0-9_]){name}-(?P<field>[A-Za-z0-9_]+)(?![A-Za-z0-9_])"

# ---------- models ----------
class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""

# ---------- core logic ----------
def find_selects(txt: str):
    out = []
    for m in SELECT_STAR_RE.finditer(txt):
        into_tab = m.group("into_tab")
        into_wa  = m.group("into_wa")
        if into_tab:
            target_type = "itab"
            target_name = into_tab
        elif into_wa:
            target_type = "wa"
            target_name = into_wa
        else:
            # No INTO -> implicit work area: table name is the "owner"
            target_type = "implicit"
            target_name = m.group("table")
        out.append({
            "text": m.group("full"),
            "table": m.group("table"),
            "target_type": target_type,
            "target_name": target_name,
            "span": m.span(0),
        })
    return out

def build_aliases(source: str) -> Dict[str, Set[str]]:
    aliases: Dict[str, Set[str]] = {}
    def add(owner, alias): aliases.setdefault(owner, set()).add(alias)

    for m in LOOP_INTO_RE.finditer(source):            add(m.group("itab"), m.group("wa"))
    for m in LOOP_ASSIGNING_RE.finditer(source):       add(m.group("itab"), f"<{m.group('fs')}>")
    for m in READ_TABLE_INTO_RE.finditer(source):      add(m.group("itab"), m.group("wa"))
    for m in READ_TABLE_ASSIGNING_RE.finditer(source): add(m.group("itab"), f"<{m.group('fs')}>")
    for m in ASSIGN_FS_ITAB_RE.finditer(source):       add(m.group("itab"), f"<{m.group('fs')}>")
    for m in HEADER_LINE_LOOP_RE.finditer(source):     add(m.group("itab"), m.group("itab"))  # header line as WA

    return aliases

def collect_used_fields(source: str, target_type: str, target_name: str, aliases: Dict[str, Set[str]]):
    """
    - itab/wa: search target and its aliases (wa, <fs>) for <name>-field references.
    - implicit: search the TABLE name as the owner (e.g., MARA-field)
    """
    names: Set[str] = set()
    if target_type == "implicit":
        names = {target_name}
    else:
        names = {target_name}
        if target_type == "itab" and target_name in aliases:
            names |= aliases[target_name]

    fields, ambiguous = set(), False

    # Ambiguity when using ASSIGN COMPONENT ... OF STRUCTURE <var or <fs>>
    if target_type != "implicit" and re.search(r"ASSIGN\s+COMPONENT\s+\w+\s+OF\s+STRUCTURE\s+" + re.escape(target_name), source, re.IGNORECASE):
        ambiguous = True
    if target_type == "itab" and re.search(r"ASSIGN\s+COMPONENT\s+\w+\s+OF\s+STRUCTURE\s+<\w+>", source, re.IGNORECASE):
        ambiguous = True

    for n in names:
        patt = re.compile(STRUCT_FIELD_RE_TMPL.format(name=re.escape(n)), re.IGNORECASE)
        for m in patt.finditer(source):
            fields.add(m.group("field").lower())

    return fields, ambiguous

def build_replacement_stmt(sel_text: str, table: str, fields: List[str], target_type: str, target_name: str) -> str:
    # Replace '*' in the original SELECT with explicit field list; keep rest intact
    head_m = re.search(r"SELECT\s+(?:SINGLE\s+)?\*\s+FROM\s+\w+", sel_text, re.IGNORECASE)
    if not head_m:
        return sel_text  # fallback

    explicit_list = " ".join(sorted(fields))
    head = head_m.group(0)
    head_repl = re.sub(r"\*", explicit_list, head, count=1)

    # If there was an INTO, normalize to CORRESPONDING FIELDS
    if target_type in ("itab", "wa"):
        into_clause = (f"INTO CORRESPONDING FIELDS OF TABLE {target_name}"
                       if target_type == "itab"
                       else f"INTO CORRESPONDING FIELDS OF {target_name}")
        # Replace any existing INTO... with the normalized INTO, or append one if missing
        if re.search(r"\bINTO\b", sel_text, re.IGNORECASE):
            sel_text_no_head = sel_text[len(head):]
            sel_text_no_head = re.sub(
                r"(?:INTO\s+TABLE\s+\w+|INTO\s+\w+)",
                into_clause,
                sel_text_no_head,
                flags=re.IGNORECASE
            )
            return head_repl + sel_text_no_head
        else:
            # No INTO present, add one before the final '.'
            body = sel_text[len(head):-1]  # strip trailing '.'
            return f"{head_repl}{body} {into_clause}."
    else:
        # implicit: keep the statement style (no INTO). Just swap the star.
        body = sel_text[len(head):]
        return head_repl + body

def apply_span_replacements(source: str, repls: List[Tuple[Tuple[int,int], str]]) -> str:
    out = source
    for (s,e), r in sorted(repls, key=lambda x: x[0][0], reverse=True):
        out = out[:s] + r + out[e:]
    return out

def concat_units(units: List[Unit]) -> str:
    return "".join((u.code or "") + "\n" for u in units)

# ---------- endpoints ----------
@app.post("/analyze-array")
def analyze_array(units: List[Unit]):
    flat_source = concat_units(units)
    aliases = build_aliases(flat_source)

    results = []
    for u in units:
        src = u.code or ""
        selects = find_selects(src)
        sel_results = []
        for sel in selects:
            used, ambiguous = collect_used_fields(
                flat_source, sel["target_type"], sel["target_name"], aliases
            )
            suggested_fields = sorted(used) if used and not ambiguous else None
            suggested_stmt = (
                build_replacement_stmt(
                    sel["text"], sel["table"], suggested_fields,
                    sel["target_type"], sel["target_name"]
                )
                if suggested_fields else None
            )
            sel_results.append({
                "table": sel["table"],
                "target_type": sel["target_type"],
                "target_name": sel["target_name"],
                "start_char_in_unit": sel["span"][0],
                "end_char_in_unit": sel["span"][1],
                "used_fields": sorted(list(used)),
                "ambiguous": ambiguous,
                "suggested_fields": suggested_fields,
                "suggested_statement": suggested_stmt
            })
        obj = json.loads(u.model_dump_json())
        obj["selects"] = sel_results
        results.append(obj)
    return results

@app.post("/remediate-array")
def remediate_array(units: List[Unit]):
    flat_source = concat_units(units)
    aliases = build_aliases(flat_source)

    results = []
    for u in units:
        src = u.code or ""
        selects = find_selects(src)
        replacements = []
        for sel in selects:
            used, ambiguous = collect_used_fields(
                flat_source, sel["target_type"], sel["target_name"], aliases
            )
            if used and not ambiguous:
                new_stmt = build_replacement_stmt(
                    sel["text"], sel["table"], sorted(used),
                    sel["target_type"], sel["target_name"]
                )
                replacements.append((sel["span"], new_stmt))
        remediated = apply_span_replacements(src, replacements)
        obj = json.loads(u.model_dump_json())
        obj["remediated_code"] = remediated
        results.append(obj)
    return results

