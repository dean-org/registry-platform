import base64
import gzip
import io
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional
from xml.sax.saxutils import escape

import qrcode
from openg2p_fastapi_common.service import BaseService

from ..config import Settings, VcDefinition

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)

_SVG_NS = "http://www.w3.org/2000/svg"
_XLINK_NS = "http://www.w3.org/1999/xlink"
ET.register_namespace("", _SVG_NS)
ET.register_namespace("xlink", _XLINK_NS)
# Any {{placeholder}} still in the SVG after substitution (value absent).
_LEFTOVER_PLACEHOLDER = re.compile(r"\{\{\s*[A-Za-z0-9_.\-]+\s*\}\}")


def _display_value(value: Any) -> Optional[str]:
    """Printable text for a claim, or None when there is nothing to show."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value).strip()
    return text or None


class PdfRenderService(BaseService):
    """Renders the printable credential.

    Returns PDF **bytes**, never a path: the agent downloads the file to their
    own machine, so nothing is written to the pod. That also keeps the service
    stateless — any replica can serve any request, and there is no temporary file
    holding citizen data.

    The card design is an SVG owned by the manifestation (shipped as a ConfigMap
    and mounted at `svg_template_dir`) so a designer can change the layout
    without touching this code. If no template is configured, a plain fallback
    layout is produced instead — an agent should never be blocked from issuing
    because a design file is missing.
    """

    def render(self, claims: Dict[str, Any], credential: Any, vc: VcDefinition) -> bytes:
        qr_payload = self._qr_payload(credential, vc)
        if vc.svg_template:
            try:
                return self._render_svg(claims, credential, qr_payload, vc)
            except Exception:
                _logger.exception(
                    "SVG rendering failed for %s; falling back to the plain layout",
                    vc.svg_template,
                )
        return self._render_fallback(claims, credential, qr_payload)

    def _qr_payload(self, credential: Any, vc: VcDefinition) -> str:
        """The compact signed QR Certify produced, or the whole VC if absent."""
        if vc.qr_claim_path and isinstance(credential, dict):
            node: Any = credential.get("credentialSubject", {})
            for part in vc.qr_claim_path.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            if isinstance(node, str) and node:
                return node
            _logger.warning(
                "No compact QR at '%s'; embedding the full credential instead. The QR "
                "will be large — configure qr_settings on the credential_config.",
                vc.qr_claim_path,
            )
        raw = json.dumps(credential, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(gzip.compress(raw)).decode()

    @staticmethod
    def _qr_png_data_uri(payload: str) -> str:
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=6, border=2
        )
        qr.add_data(payload)
        qr.make(fit=True)
        buf = io.BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    def _render_svg(
        self, claims: Dict[str, Any], credential: Any, qr_payload: str, vc: VcDefinition
    ) -> bytes:
        import cairosvg

        template_path = os.path.join(_config.svg_template_dir, vc.svg_template)
        with open(template_path, encoding="utf-8") as handle:
            svg = handle.read()

        # Claims with no value are not shown: rows tagged data-field="<claim>"
        # are dropped (and the rest re-flowed) before substitution.
        shown = {k: _display_value(v) for k, v in claims.items()}
        shown = {k: v for k, v in shown.items() if v is not None}
        if "data-field" in svg:
            svg = self._prune_empty_fields(svg, shown)

        substitutions = {
            "title": _config.pdf_title,
            "issuerName": _config.pdf_issuer_name,
            "issuer": str(credential.get("issuer", "")) if isinstance(credential, dict) else "",
            # Photograph is deferred to Phase 2; leave the placeholder empty so an
            # existing design containing {{photo}} still renders.
            "photo": "",
        }
        substitutions.update({k: escape(v) for k, v in shown.items()})
        # The QR is a base64 data URI: set after, and never escaped or touched.
        substitutions["qr"] = self._qr_png_data_uri(qr_payload)
        for key, value in substitutions.items():
            svg = svg.replace("{{" + key + "}}", value).replace("{{ " + key + " }}", value)
        # A placeholder with no value must never print as literal "{{name}}".
        svg = _LEFTOVER_PLACEHOLDER.sub("", svg)

        out = io.BytesIO()
        cairosvg.svg2pdf(bytestring=svg.encode("utf-8"), write_to=out)
        return out.getvalue()

    @staticmethod
    def _prune_empty_fields(svg: str, shown: Dict[str, str]) -> str:
        """Drop `data-field` elements whose claim has no value.

        A grid container (`data-grid-columns`, `data-grid-col-width`,
        `data-grid-row-height`) lays its `data-field` children out row by row,
        so removing an empty field closes the gap instead of leaving a hole.
        A `data-field` element outside any grid is simply removed when empty.
        """
        root = ET.fromstring(svg.encode("utf-8"))
        parent = {child: par for par in root.iter() for child in par}

        def has_value(el: ET.Element) -> bool:
            return el.get("data-field", "") in shown

        for grid in [e for e in root.iter() if e.get("data-grid-columns")]:
            columns = max(int(grid.get("data-grid-columns", "1")), 1)
            col_width = float(grid.get("data-grid-col-width", "0"))
            row_height = float(grid.get("data-grid-row-height", "0"))
            index = 0
            for child in list(grid):
                if child.get("data-field") is None:
                    continue
                if not has_value(child):
                    grid.remove(child)
                    continue
                x = (index % columns) * col_width
                y = (index // columns) * row_height
                child.set("transform", f"translate({x:g},{y:g})")
                index += 1

        for el in [e for e in root.iter() if e.get("data-field") is not None]:
            if el in parent and parent[el] is not None and not has_value(el):
                try:
                    parent[el].remove(el)
                except ValueError:  # already removed with a grid
                    pass
        return ET.tostring(root, encoding="unicode")

    def _render_fallback(
        self, claims: Dict[str, Any], credential: Any, qr_payload: str
    ) -> bytes:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, _config.pdf_title, ln=True)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 6, f"Issued by {_config.pdf_issuer_name}", ln=True)
        pdf.ln(4)

        pdf.set_font("Helvetica", size=12)
        for key, value in claims.items():
            text = _display_value(value)
            if text is None:
                continue
            pdf.cell(0, 7, f"{key}: {text}", ln=True)
        pdf.ln(4)

        qr_img = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=6, border=2
        )
        qr_img.add_data(qr_payload)
        qr_img.make(fit=True)
        buf = io.BytesIO()
        qr_img.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
        buf.seek(0)
        pdf.image(buf, w=60)
        pdf.ln(2)
        pdf.set_font("Helvetica", size=8)
        pdf.cell(0, 5, "Scan the QR to verify this credential offline.", ln=True)

        return bytes(pdf.output())