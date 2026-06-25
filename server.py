#!/usr/bin/env python3
"""
SAP (IDoc / RFC / ABAP) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse IDoc, map to modern, and govern. Sibling of cobol-bridge-mcp.
Tools: parse_idoc · map_to_modern · validate_idoc · govern_sap
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("SAP Bridge", instructions="Bridge SAP IDoc/RFC/ABAP legacy to ONE OS — parse, map, govern (SOX/GRC).")

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
    p = parse_idoc(idoc)
    flags = []
    if p.message_type in ("DEBMAS", "CREMAS", "MATMAS"):
        flags.append(f"Master-data IDoc ({p.message_type}) — change-control + SoD review required")
    return Governance(risk_flags=flags,
                      frameworks=["SAP GRC", "SOX (ITGC)", "GDPR", "EU AI Act (if automated decisioning)"],
                      note="CSOAI governs the bridge: IDoc + lineage attestable on the ledger.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
