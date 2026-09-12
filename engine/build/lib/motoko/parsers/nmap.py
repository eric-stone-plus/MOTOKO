"""nmap output parser — XML (-oX -) -> services + per-host scan stamp.

R7-5: nmap is the ONLY producer of ``service`` facts, and the SMB chain
depends on them. The rule runs ``nmap -sV -oX - {host}``; this parser walks
the XML port table and emits:

* one ``services`` entry per open port (port/protocol/service_name/product/
  version/extra) — persisted via ``add_service`` on the host's asset;
* one ``host``-typed asset carrying ``nmap_host`` so the per-host scan gate
  (R7-4) closes and the host never re-mints an nmap hypothesis.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from . import Parser, register


@register
class NmapParser(Parser):
    tool = "nmap"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        services: list[dict] = []
        dead: list[str] = []
        target_host = (action or {}).get("host") or ""

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            dead.append((stdout or "")[:2000])
            return self._result(summary="nmap: unparseable XML",
                                dead_letter=dead)

        for host in root.iter("host"):
            for port in host.iter("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                if service is None:
                    continue
                product = service.get("product") or ""
                version = service.get("version") or ""
                name = service.get("name") or "unknown"
                extra = service.get("extrainfo") or ""
                services.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service_name": name,
                    "product": product,
                    "version": version,
                    "banner": extra,
                })
        # per-host stamp: gate for R-RECON-NMAP-001 (R7-4)
        if target_host:
            assets.append(self._asset(
                type_="host", value=target_host,
                extra={"nmap_host": target_host}))
        return self._result(
            summary=f"nmap: {len(services)} open ports",
            assets=assets, services=services, dead_letter=dead)
