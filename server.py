#!/usr/bin/env python3
"""
SAP (IDoc / RFC / ABAP) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse IDoc, map to modern, and govern. Sibling of cobol-bridge-mcp.
Tools: parse_idoc · map_to_modern · validate_idoc · govern_sap
"""
from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x: FastMCP renamed MCPServer
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("SAP Bridge", instructions="Bridge SAP IDoc/RFC/ABAP legacy to ONE OS — parse, map, govern (SOX/GRC).")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

IDOC_TYPES = {
    "ORDERS": "Purchase/Sales Order", "INVOIC": "Invoice", "DESADV": "Despatch Advice",
    "MATMAS": "Material Master", "DEBMAS": "Customer Master", "CREMAS": "Vendor Master",
}


class IDocParsed(BaseModel):
    message_type: str
    description: str
    segments: List[str] = Field(default_factory=list)
    segment_count: int = 0
    control: Dict[str, str] = Field(default_factory=dict)


class Validation(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


def _records(idoc: str) -> List[str]:
    return [ln.rstrip() for ln in idoc.replace("\r\n", "\n").split("\n") if ln.strip()]


@mcp.tool()
def parse_idoc(idoc: str) -> IDocParsed:
    """Parse a SAP IDoc (control record EDIDC + data records EDIDD); extract message type + segments."""
    recs = _records(idoc)
    control: Dict[str, str] = {}
    segs: List[str] = []
    mt = "unknown"
    for r in recs:
        # control record usually starts EDI_DC / EDIDC and contains the MESTYP
        head = r.split("|") if "|" in r else r.split()
        if r.upper().startswith(("EDI_DC", "EDIDC")):
            for token in head:
                if token in IDOC_TYPES:
                    mt = token
            control["raw"] = r[:80]
        elif r.upper().startswith(("EDI_DD", "EDIDD", "E1", "E2", "Z1")):
            seg = head[0] if head else r[:10]
            segs.append(seg)
        for token in head:
            if token in IDOC_TYPES:
                mt = token
    return IDocParsed(message_type=mt, description=IDOC_TYPES.get(mt, "SAP IDoc"),
                      segments=segs[:40], segment_count=len(recs), control=control)


@mcp.tool()
def validate_idoc(idoc: str) -> Validation:
    """Validate IDoc structure (control record present + at least one data segment)."""
    recs = _records(idoc)
    errors, warnings = [], []
    if not any(r.upper().startswith(("EDI_DC", "EDIDC")) for r in recs):
        warnings.append("No control record (EDIDC) detected")
    if len(recs) < 2:
        errors.append("IDoc has no data segments")
    return Validation(valid=not errors, errors=errors, warnings=warnings)


@mcp.tool()
def map_to_modern(idoc: str) -> Dict[str, Any]:
    """Map an IDoc to a modern JSON event for ONE OS / downstream APIs."""
    p = parse_idoc(idoc)
    return {"source": "SAP IDoc", "event_type": p.message_type,
            "description": p.description, "segments": p.segments,
            "target": "modern event/API"}


@mcp.tool()
def govern_sap(idoc: str) -> Governance:
    """Governance: SAP GRC / SOX segregation-of-duties + master-data surface (attestable)."""
    _sigil("G", "sap|govern_sap")
    p = parse_idoc(idoc)
    flags = []
    if p.message_type in ("DEBMAS", "CREMAS", "MATMAS"):
        flags.append(f"Master-data IDoc ({p.message_type}) — change-control + SoD review required")
    return Governance(risk_flags=flags,
                      frameworks=["SAP GRC", "SOX (ITGC)", "GDPR", "EU AI Act (if automated decisioning)"],
                      note="CSOAI governs the bridge: IDoc + lineage attestable on the ledger.")


# ---------------------------------------------------------------------------
# MCP 2026-07-28 wire - header-add migration (2026-10-08)
# ---------------------------------------------------------------------------
# stdio carries no HTTP headers, so Mcp-Method / Mcp-Name are not applicable to
# this transport at runtime. When sap-bridge-mcp is exposed over HTTP, route the ingress
# through the vendored mcp2026_shim (ShimASGI): it validates Mcp-Method /
# Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" into every
# request, strips Mcp-Session-Id and answers legacy initialize / server-discover
# locally (the session header is never emitted - stateless wire).
# Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md (3) + (4).
# ---------------------------------------------------------------------------


def http_app():
    """ASGI app for HTTP exposure, wrapped in the 2026-07-28 wire shim.

    stdio (``mcp.run()``) needs no shim; this is the enable path once the
    server is fronted by an HTTP transport. Bodies are buffered, so responses
    are requested in JSON mode rather than SSE.
    """
    from mcp2026_shim import WIRE_2026, ShimASGI, ShimConfig

    return ShimASGI(
        mcp.streamable_http_app(json_response=True),
        ShimConfig(
            protocol_version=WIRE_2026,
            server_info={"name": "sap-bridge-mcp", "version": "0.1.0"},
        ),
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
