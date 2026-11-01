"""Parse existing Nmap XML output into asset and service inventory."""

import xml.etree.ElementTree as ET

from vulnwatch.database import connect


class NmapImportError(ValueError):
    """The uploaded file is not a supported Nmap XML document."""


def parse_nmap_xml(content: bytes) -> list[dict]:
    if not content or len(content) > 5_000_000:
        raise NmapImportError("Upload a non-empty Nmap XML file smaller than 5 MB.")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        raise NmapImportError("The uploaded file is not valid XML.") from error
    if root.tag != "nmaprun":
        raise NmapImportError("The XML root element must be nmaprun.")

    hosts = []
    for host in root.findall("host"):
        if host.find("status") is not None and host.find("status").get("state") != "up":
            continue
        addresses = host.findall("address")
        address = next((item.get("addr") for item in addresses if item.get("addrtype") in ("ipv4", "ipv6")), None)
        if not address:
            continue
        hostname_element = host.find("./hostnames/hostname")
        hostname = hostname_element.get("name") if hostname_element is not None else None
        os_match = host.find("./os/osmatch")
        operating_system = os_match.get("name") if os_match is not None else None
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.get("state") != "open":
                continue
            try:
                port_number = int(port.get("portid", "0"))
            except ValueError as error:
                raise NmapImportError("An Nmap service has an invalid port number.") from error
            if not 1 <= port_number <= 65535:
                raise NmapImportError("An Nmap service port must be between 1 and 65535.")
            services.append({
                "protocol": port.get("protocol", "tcp"),
                "port": port_number,
                "service_name": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            })
        hosts.append({"ip_address": address, "hostname": hostname, "operating_system": operating_system, "services": services})
    return hosts


def store_nmap_inventory(hosts: list[dict]) -> tuple[int, int]:
    """Persist parsed hosts and services without creating vulnerability findings."""
    asset_count = 0
    service_count = 0
    with connect() as connection:
        for host in hosts:
            name = host["hostname"] or host["ip_address"]
            connection.execute(
                """INSERT INTO assets (name, ip_address, hostname, operating_system, source)
                   VALUES (?, ?, ?, ?, 'nmap')
                   ON CONFLICT(ip_address) DO UPDATE SET name=excluded.name,
                       hostname=excluded.hostname, operating_system=excluded.operating_system,
                       source='nmap'""",
                (name, host["ip_address"], host["hostname"], host["operating_system"]),
            )
            asset = connection.execute("SELECT id FROM assets WHERE ip_address = ?", (host["ip_address"],)).fetchone()
            asset_count += 1
            for service in host["services"]:
                connection.execute(
                    """INSERT INTO asset_services (asset_id, protocol, port, service_name, product, version)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(asset_id, protocol, port) DO UPDATE SET service_name=excluded.service_name,
                           product=excluded.product, version=excluded.version""",
                    (asset["id"], service["protocol"], service["port"], service["service_name"],
                     service["product"], service["version"]),
                )
                service_count += 1
    return asset_count, service_count
