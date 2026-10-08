"""Evaluate DDR announcements using three measured OS profiles and real DoH exchanges."""
import argparse
import os
# Only DDR_TLS_KEYLOG explicitly enables local key-log output.
os.environ.pop('SSLKEYLOGFILE', None)
from contextlib import nullcontext
import asyncio
import base64
from collections import Counter
import datetime as dt
import hashlib
import importlib.metadata
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import time
import urllib.parse
import warnings

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset, ConnectionTerminated
import uritemplate
from service_identity.cryptography import verify_certificate_hostname, verify_certificate_ip_address
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived as H3Data
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated as QuicTerminated


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def unique(values):
    return list(dict.fromkeys(values))


def public_address(value):
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast and not address.is_reserved


def store(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]


def record_info(record):
    params = record.params
    item = {"priority": record.priority, "target": record.target.to_text().lower(),
            "text": record.to_text(), "alpn": [], "ipv4hint": [], "ipv6hint": [],
            "port": 443, "mandatory": [], "dohpath": None}
    if 1 in params:
        item["alpn"] = [value.decode("ascii", "backslashreplace") for value in params[1].ids]
    if 0 in params:
        item["mandatory"] = [int(key) for key in params[0].keys]
    for key, name in [(4, "ipv4hint"), (6, "ipv6hint")]:
        if key in params:
            item[name] = list(params[key].addresses)
    if 3 in params:
        item["port"] = params[3].port
    if 7 in params:
        item["dohpath"] = params[7].value.decode("utf-8")
    issues = []
    if item["priority"] == 0:
        issues.append("aliasmode_requires_followup")
    if item["target"] in [".", "resolver.arpa."]:
        issues.append("invalid_ddr_target")
    if not item["alpn"]:
        issues.append("missing_alpn")
    if any(key not in params for key in item["mandatory"]):
        issues.append("missing_mandatory_parameter")
    if any(key not in {0, 1, 2, 3, 4, 6, 7} for key in item["mandatory"]):
        issues.append("unimplemented_mandatory_parameter")
    if not 1 <= item["port"] <= 65535:
        issues.append("invalid_port")
    if any(protocol in ["h2", "h3"] for protocol in item["alpn"]):
        template = item["dohpath"]
        if not template or "dns" not in uritemplate.variables(template):
            issues.append("missing_dns_uri_variable")
        elif not template.startswith("/") or template.startswith("//") or "#" in template:
            issues.append("invalid_dohpath")
        else:
            try:
                make_path(template, "GET", b"test")
                make_path(template, "POST", b"test")
            except ValueError:
                issues.append("invalid_expanded_dohpath")
    item["issues"] = issues
    return item


def make_path(template, method, wire):
    variables = {"dns": base64.urlsafe_b64encode(wire).rstrip(b"=").decode()} if method == "GET" else {}
    path = uritemplate.expand(template, variables)
    if not path.startswith("/") or path.startswith("//") or "#" in path or "{" in path or "}" in path:
        raise ValueError("invalid_expanded_path")
    return urllib.parse.quote(path, safe="/?:@!$&'()*+,;=-._~%")


def addresses(section, target=None):
    return unique(r.address for rr in section if rr.rdtype in [1, 28]
                  and (target is None or rr.name.to_text().lower() == target)
                  for r in rr)


def answer_addresses(response, target):
    names = {target.lower()}
    for _ in range(8):
        found = {r.target.to_text().lower() for rr in response.answer
                 if rr.rdtype == 5 and rr.name.to_text().lower() in names for r in rr}
        if found <= names:
            break
        names |= found
    return unique(r.address for rr in response.answer if rr.rdtype in [1, 28]
                  and rr.name.to_text().lower() in names for r in rr)


def profile_addresses(profile, service, response, original, resolved=None):
    hints = service["ipv4hint"] + service["ipv6hint"]
    if profile == "android":
        pool = addresses(response.additional) or hints
        return [ip for ip in unique(pool) if ip == original]
    if profile == "windows":
        return unique(addresses(response.additional, service["target"]) + hints)
    if service["ipv4hint"]:
        return unique(hints + addresses(response.additional, service["target"]))
    return unique((resolved or []) + service["ipv6hint"])


def certificate_info(certificate, target):
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        ips, names = [], []
    try:
        identity = target.rstrip(".")
        try:
            ipaddress.ip_address(identity)
        except ValueError:
            verify_certificate_hostname(certificate, identity)
        else:
            verify_certificate_ip_address(certificate, identity)
        name_match = True
    except Exception:
        name_match = False
    return {"certificate_ip_san": ips, "certificate_dns_san": names,
            "target_name_match": name_match, "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "certificate_sha256": hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()}


def certificate_ok(profile, original, result):
    if not result.get("chain_valid") or not result.get("target_name_match"):
        return False
    return profile == "android" or original in result.get("certificate_ip_san", [])


def save_tls_peer(sock, folder, target):
    result = {}
    if hasattr(sock._sslobj, "get_unverified_chain"):
        chain = sock._sslobj.get_unverified_chain() or []
        pem = b"".join(value.public_bytes().encode() if isinstance(value.public_bytes(), str)
                       else value.public_bytes() for value in chain)
        if pem:
            (folder / "chain.pem").write_bytes(pem)
            certificates = x509.load_pem_x509_certificates(pem)
            result.update(certificate_info(certificates[0], target))
    if not result:
        der = sock.getpeercert(binary_form=True)
        if der:
            result.update(certificate_info(x509.load_der_x509_certificate(der), target))
            (folder / "leaf.der").write_bytes(der)
    return result


def tls_probe(ip, port, target, folder, timeout):
    folder.mkdir(parents=True, exist_ok=True)
    result = {"utc": utc(), "F": ip, "port": port, "sni": target.rstrip("."), "chain_valid": False,
              "stage": "tcp_connect", "alpn_requested": ["h2", "http/1.1"]}
    started = time.monotonic()
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.keylog_filename = str(folder / "tls.keys") if os.environ.get("DDR_TLS_KEYLOG") == "1" else None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            result["stage"] = "tls_handshake"
            with context.wrap_socket(raw, server_hostname=target.rstrip("."), do_handshake_on_connect=False) as tls:
                try:
                    tls.do_handshake()
                    result.update(chain_valid=True, tls_version=tls.version(), alpn=tls.selected_alpn_protocol())
                finally:
                    try:
                        result.update(save_tls_peer(tls, folder, target))
                    except Exception as error:
                        result["certificate_capture_error"] = str(error)
            result["stage"] = "complete"
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    result["elapsed_seconds"] = round(time.monotonic() - started, 4)
    store(folder / "result.json", result)
    return result


def check_response(query, headers, body):
    result = {"http_status": int(headers.get(":status", 0)), "response_headers": headers,
              "doh_protocol_valid": False, "positive_dns_answer": False}
    if result["http_status"] != 200:
        result["failure"] = "http_status_" + str(result["http_status"])
        return result
    if headers.get("content-type", "").split(";")[0].lower() != "application/dns-message":
        result["failure"] = "invalid_content_type"
        return result
    try:
        response = dns.message.from_wire(body)
        if not query.is_response(response) or response.flags & dns.flags.TC:
            raise ValueError("DNS response does not match query or is truncated")
        result.update(doh_protocol_valid=True, dns_rcode=dns.rcode.to_text(response.rcode()),
                      dns_answer=response.to_text(), positive_dns_answer=response.rcode() == 0 and bool(response.answer))
        if not result["positive_dns_answer"]:
            result["failure"] = "dns_no_positive_answer"
    except Exception as error:
        result["failure"] = "invalid_dns_body: " + str(error)
    return result


def h2_probe(ip, port, target, authority, method, template, folder, timeout):
    folder.mkdir(parents=True, exist_ok=True)
    query = dns.message.make_query("example.com.", "A")
    query.id = 0
    wire = query.to_wire()
    path = make_path(template, method, wire)
    (folder / "dns-query.bin").write_bytes(wire)
    result = {"utc": utc(), "F": ip, "port": port, "sni": target.rstrip("."),
              "authority": authority, "method": method, "path": path,
              "chain_valid": False, "doh_protocol_valid": False, "positive_dns_answer": False,
              "stage": "tcp_connect"}
    context = ssl.create_default_context(cafile=certifi.where())
    context.set_alpn_protocols(["h2"])
    context.keylog_filename = str(folder / "tls.keys") if os.environ.get("DDR_TLS_KEYLOG") == "1" else None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            result["stage"] = "tls_handshake"
            with context.wrap_socket(raw, server_hostname=target.rstrip(".")) as tls:
                result.update(chain_valid=True, alpn=tls.selected_alpn_protocol(), tls_version=tls.version())
                result.update(save_tls_peer(tls, folder, target))
                if result["alpn"] != "h2":
                    raise ValueError("h2_not_negotiated")
                connection = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
                connection.initiate_connection()
                headers = [(":method", method), (":scheme", "https"), (":authority", authority),
                           (":path", path), ("accept", "application/dns-message"),
                           ("user-agent", "DDR-Interop-Research/20261002")]
                if method == "POST":
                    headers += [("content-type", "application/dns-message"), ("content-length", str(len(wire)))]
                result["request_headers"] = headers
                connection.send_headers(1, headers, end_stream=method == "GET")
                if method == "POST":
                    connection.send_data(1, wire, end_stream=True)
                tls.sendall(connection.data_to_send())
                result["stage"] = "http_response"
                response_headers, body = {}, bytearray()
                deadline = time.monotonic() + timeout
                ended = False
                while not ended:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("HTTP/2 response deadline")
                    tls.settimeout(remaining)
                    data = tls.recv(65536)
                    if not data:
                        raise ValueError("HTTP/2 EOF before stream end")
                    for event in connection.receive_data(data):
                        if isinstance(event, ResponseReceived) and event.stream_id == 1:
                            response_headers = dict(event.headers)
                        elif isinstance(event, DataReceived) and event.stream_id == 1:
                            body.extend(event.data)
                            connection.acknowledge_received_data(event.flow_controlled_length, 1)
                            if len(body) > 65535:
                                raise ValueError("response_body_too_large")
                        elif isinstance(event, StreamEnded) and event.stream_id == 1:
                            ended = True
                        elif isinstance(event, (StreamReset, ConnectionTerminated)) and not ended:
                            raise ValueError(str(event))
                    outgoing = connection.data_to_send()
                    if outgoing and not ended:
                        tls.sendall(outgoing)
                (folder / "dns-response.bin").write_bytes(body)
                result.update(check_response(query, response_headers, bytes(body)))
                result["stage"] = "complete"
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    store(folder / "result.json", result)
    return result


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.done = asyncio.get_running_loop().create_future()
        self.headers, self.body, self.alpn = {}, bytearray(), None
        self.stream_id = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.alpn = event.alpn_protocol
        if isinstance(event, QuicTerminated) and not self.done.done():
            self.done.set_exception(ConnectionError(str(event)))
        for incoming in self.http.handle_event(event):
            if not isinstance(incoming, (HeadersReceived, H3Data)) or incoming.stream_id != self.stream_id:
                continue
            if isinstance(incoming, HeadersReceived):
                self.headers.update({k.decode(): v.decode() for k, v in incoming.headers})
            else:
                self.body.extend(incoming.data)
                if len(self.body) > 65535 and not self.done.done():
                    self.done.set_exception(ValueError("response_body_too_large"))
            if incoming.stream_ended and not self.done.done():
                self.done.set_result(True)


async def h3_probe(ip, port, target, authority, template, folder, timeout):
    folder.mkdir(parents=True, exist_ok=True)
    query = dns.message.make_query("example.com.", "A")
    query.id = 0
    wire = query.to_wire()
    (folder / "dns-query.bin").write_bytes(wire)
    path = make_path(template, "GET", wire)
    result = {"utc": utc(), "F": ip, "port": port, "sni": target.rstrip("."), "authority": authority,
              "method": "GET", "path": path, "chain_valid": False,
              "doh_protocol_valid": False, "positive_dns_answer": False, "stage": "quic_handshake"}
    instances = []

    def factory(*args, **kwargs):
        instance = H3Client(*args, **kwargs)
        instances.append(instance)
        return instance

    with ((folder / "tls.keys").open("w") if os.environ.get("DDR_TLS_KEYLOG") == "1" else nullcontext(None)) as keys:
        config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=target.rstrip("."),
                                   cafile=certifi.where(), idle_timeout=timeout, secrets_log_file=keys)
        try:
            async with asyncio.timeout(timeout * 2):
                async with connect(ip, port, configuration=config, create_protocol=factory) as client:
                    result.update(chain_valid=True, alpn=client.alpn, stage="http_response")
                    client.stream_id = client._quic.get_next_available_stream_id()
                    headers = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", authority.encode()),
                               (b":path", path.encode()), (b"accept", b"application/dns-message")]
                    result["request_headers"] = [(k.decode(), v.decode()) for k, v in headers]
                    client.http.send_headers(client.stream_id, headers, end_stream=True)
                    client.transmit()
                    await asyncio.wait_for(client.done, timeout)
                    (folder / "dns-response.bin").write_bytes(client.body)
                    result.update(check_response(query, client.headers, bytes(client.body)))
                    result["stage"] = "complete"
        except Exception as error:
            result.update(error_type=type(error).__name__, error=str(error))
        finally:
            if instances:
                client = instances[0]
                tls = client._quic.tls
                leaf = getattr(tls, "_peer_certificate", None)
                if leaf is not None:
                    result.update(certificate_info(leaf, target))
                    chain = [leaf] + list(getattr(tls, "_peer_certificate_chain", []))
                    (folder / "chain.pem").write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain))
                if client.done.done() and not client.done.cancelled():
                    client.done.exception()
                elif not client.done.done():
                    client.done.cancel()
    store(folder / "result.json", result)
    return result


class Survey:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.output)
        self.cache = {}
        self.connections = asyncio.Semaphore(args.connections)
        self.endpoints = {}
        self.counts = Counter()
        self.dns_semaphore = asyncio.Semaphore(32)

    async def cached(self, category, values, action):
        key = category + "-" + digest(values)
        if key not in self.cache:
            folder = self.out / "endpoints" / key
            existing = folder / "result.json"
            if existing.exists():
                return key, json.loads(existing.read_text())

            async def execute():
                ip = values[0]
                semaphore = self.endpoints.setdefault(ip, asyncio.Semaphore(2))
                async with self.connections, semaphore:
                    result = await action(folder)
                    await asyncio.sleep(0.2)
                    return result
            self.cache[key] = asyncio.create_task(execute())
        return key, await self.cache[key]

    async def dns_query(self, original, name, qtype, evidence):
        query = dns.message.make_query(name, qtype, use_edns=0, payload=1232)
        record = {"qname": name, "qtype": qtype, "utc": utc(),
                  "query_b64": base64.b64encode(query.to_wire()).decode(), "attempts": []}
        final = None
        async with self.dns_semaphore:
            for transport in ["udp", "tcp"]:
                row = {"transport": transport}
                try:
                    method = dns.asyncquery.udp if transport == "udp" else dns.asyncquery.tcp
                    response = await method(query, original, timeout=self.args.timeout)
                    row["response_b64"] = base64.b64encode(response.wire or response.to_wire()).decode()
                    final = response
                except Exception as error:
                    row.update(error=type(error).__name__, message=str(error))
                record["attempts"].append(row)
                if final is not None and not final.flags & dns.flags.TC:
                    break
        evidence.append(record)
        return final

    async def get_services(self, original, response, name, evidence, visited=None):
        visited = set() if visited is None else visited
        name = name.lower()
        if name in visited or len(visited) >= 8:
            return [], ["alias_loop_or_depth_limit"]
        visited.add(name)
        for rr in response.answer:
            if rr.name.to_text().lower() == name and rr.rdtype == 5:
                name = rr[0].target.to_text().lower()
                return await self.get_services(original, response, name, evidence, visited)
        records = [r for rr in response.answer if rr.name.to_text().lower() == name and rr.rdtype == 64 for r in rr]
        if not records:
            if name != "_dns.resolver.arpa.":
                new = await self.dns_query(original, name, "SVCB", evidence)
                if new is not None and new.rcode() == 0:
                    records = [r for rr in new.answer if rr.rdtype == 64 and rr.name.to_text().lower() == name for r in rr]
                    response = new
            if not records:
                return [], ["no_service_record_at_expected_owner"]
        services, notes = [], []
        for record in sorted(records, key=lambda r: r.priority):
            if record.priority == 0:
                alias = record.target.to_text().lower()
                new = await self.dns_query(original, alias, "SVCB", evidence)
                if new is not None and new.rcode() == 0:
                    found, more = await self.get_services(original, new, alias, evidence, visited.copy())
                    services.extend(found)
                    notes.extend(more)
                else:
                    notes.append("alias_resolution_failed")
            else:
                try:
                    services.append((record_info(record), response))
                except Exception as error:
                    notes.append("record_parse_error: " + str(error))
        return services, notes

    async def process(self, discovery):
        original = discovery["A"]
        responses = [attempt for attempt in discovery["attempts"] if "response_b64" in attempt]
        if not responses:
            return None
        response = dns.message.from_wire(base64.b64decode(responses[-1]["response_b64"]))
        if response.rcode() != 0 or not any(rr.rdtype in [5, 64] for rr in response.answer):
            return None
        row = {"A": original, "vantage": self.args.vantage, "utc": utc(), "services": [],
               "followup_dns": [], "profiles": {}, "native_os_execution": False}
        services, notes = await self.get_services(original, response, "_dns.resolver.arpa.", row["followup_dns"])
        row["discovery_notes"] = notes
        resolved = {}
        for service, service_response in services:
            entry = dict(service)
            entry["additional_addresses"] = addresses(service_response.additional)
            entry["target_additional_addresses"] = addresses(service_response.additional, service["target"])
            entry["profiles"] = {}
            row["services"].append(entry)
            for profile in ["windows", "android", "macos"]:
                check = {"candidates": [], "paths": [], "result": "not_selected"}
                entry["profiles"][profile] = check
                if service["issues"]:
                    check["reason"] = ";".join(service["issues"])
                    continue
                alpn = service["alpn"]
                wanted = "h3" if profile == "android" else "h2"
                if wanted not in alpn and not (profile == "windows" and "h3" in alpn):
                    check["reason"] = "no_doh_protocol_for_profile"
                    continue
                if not service["dohpath"]:
                    check["reason"] = "missing_dohpath"
                    continue
                if profile == "windows" and "h2" not in alpn:
                    check["selection_note"] = "h3_only_windows_h2_behavior_from_controlled_experiment"
                lookup = []
                if profile == "macos" and not service["ipv4hint"]:
                    target = service["target"]
                    if target not in resolved:
                        resolved[target] = []
                        for qtype in ["A", "AAAA"]:
                            answer = await self.dns_query(original, target, qtype, row["followup_dns"])
                            if answer is not None and answer.rcode() == 0:
                                resolved[target] += answer_addresses(answer, target)
                    lookup = resolved[target]
                    check["address_source"] = "query_target_at_original_resolver_no_ipv4hint"
                candidates = profile_addresses(profile, service, service_response, original, lookup)
                check["candidates"] = candidates
                check["excluded_nonpublic"] = [ip for ip in candidates if not public_address(ip)]
                candidates = [ip for ip in candidates if public_address(ip)]
                if not candidates:
                    check.update(result="discovery_ineligible", reason="no_eligible_public_address")
                    continue
                port, target, template = service["port"], service["target"], service["dohpath"]
                for ip in candidates:
                    path = {"F": ip, "port": port, "protocol": wanted, "sni": target.rstrip(".")}
                    check["paths"].append(path)
                    authority = original if profile == "macos" else target.rstrip(".")
                    try:
                        if ipaddress.ip_address(authority).version == 6:
                            authority = "[" + authority + "]"
                    except ValueError:
                        pass
                    if port != 443:
                        authority += ":" + str(port)
                    path["authority"] = authority
                    method = "POST" if profile == "windows" else "GET"
                    path["method"] = method
                    if profile == "android":
                        key, result = await self.cached("h3", [ip, port, target, authority, template],
                            lambda folder: h3_probe(ip, port, target, authority, template, folder, self.args.timeout))
                        path.update(http_evidence=key, certificate_ok=certificate_ok(profile, original, result),
                                    http_status=result.get("http_status"), doh_protocol_valid=result.get("doh_protocol_valid", False),
                                    positive_dns_answer=result.get("positive_dns_answer", False),
                                    error=result.get("error", result.get("failure")))
                    else:
                        key, cert = await self.cached("tls", [ip, port, target],
                            lambda folder: asyncio.to_thread(tls_probe, ip, port, target, folder, self.args.timeout))
                        path.update(tls_evidence=key, chain_valid=cert.get("chain_valid", False),
                                    target_name_match=cert.get("target_name_match", False),
                                    original_ip_san_match=original in cert.get("certificate_ip_san", []),
                                    certificate_ok=certificate_ok(profile, original, cert))
                        if not path["certificate_ok"]:
                            path.update(success=False, stop="certificate", error=cert.get("error"),
                                        http_not_attempted="certificate_conditions_not_met")
                            continue
                        key, result = await self.cached("h2", [ip, port, target, authority, method, template],
                            lambda folder: asyncio.to_thread(h2_probe, ip, port, target, authority, method,
                                                           template, folder, self.args.timeout))
                        path.update(http_evidence=key, http_status=result.get("http_status"),
                                    doh_protocol_valid=result.get("doh_protocol_valid", False),
                                    positive_dns_answer=result.get("positive_dns_answer", False),
                                    error=result.get("error", result.get("failure")))
                        path["certificate_ok"] = certificate_ok(profile, original, result)
                    path["success"] = path["certificate_ok"] and path["positive_dns_answer"]
                    path["stop"] = "complete" if path["success"] else "http_or_dns" if path["certificate_ok"] else "certificate_or_handshake"
                check["result"] = "pass" if any(p.get("success") for p in check["paths"]) else "endpoint_conditions_failed"
        for profile in ["windows", "android", "macos"]:
            checks = [entry["profiles"][profile] for entry in row["services"]]
            if any(check["result"] == "pass" for check in checks):
                outcome = "pass"
            elif any(check["result"] == "endpoint_conditions_failed" for check in checks):
                outcome = "endpoint_conditions_failed"
            elif any(check["result"] == "discovery_ineligible" for check in checks):
                outcome = "discovery_ineligible"
            else:
                outcome = "no_compatible_service"
            row["profiles"][profile] = outcome
        store(self.out / "resolvers" / (original + ".json"), row)
        return row

    async def run(self):
        self.out.mkdir(parents=True, exist_ok=True)
        store(self.out / "endpoint-plan.json", {"utc": utc(), "vantage": self.args.vantage,
              "profiles": {"windows": "H2 POST, SNI T, authority T, chain+T+original IP SAN",
                           "android": "opportunistic DDR enabled; H3 GET; SNI/authority T; F in original DNS list; chain+T",
                           "macos": "H2 GET, SNI T, authority A, chain+T+original IP SAN; no ipv4hint -> query A for target A/AAAA"},
              "selection": "all eligible records and public IPv4/IPv6 addresses; any successful path per original resolver",
              "native_os_execution": False, "trust": "certifi Mozilla CA bundle; OS-specific trust stores are not emulated",
              "trust_sha256": hashlib.sha256(Path(certifi.where()).read_bytes()).hexdigest(),
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "versions": {name: importlib.metadata.version(name) for name in ["dnspython", "h2", "cryptography", "certifi", "aioquic", "uritemplate"]},
              "limits": {"workers": self.args.workers, "connections": self.args.connections, "per_destination_concurrency": 2,
                         "pause_after_connection": 0.2, "timeout": self.args.timeout}})
        queue = asyncio.Queue(maxsize=256)
        completed = set(p.stem for p in (self.out / "resolvers").glob("*.json")) if (self.out / "resolvers").exists() else set()
        started = time.monotonic()

        async def worker():
            while True:
                item = await queue.get()
                if item is None:
                    queue.task_done()
                    return
                try:
                    row = await self.process(item)
                    if row:
                        for profile, status in row["profiles"].items():
                            self.counts[profile + ":" + status] += 1
                        self.counts["resolvers_checked"] += 1
                except Exception as error:
                    store(self.out / "errors" / (item["A"] + ".json"),
                          {"A": item["A"], "error": str(error), "type": type(error).__name__})
                    self.counts["processing_errors"] += 1
                queue.task_done()

        def progress(final=False):
            store(self.out / "endpoint-progress.json", {"utc": utc(), "complete": final,
                  "counts": dict(self.counts), "queued": queue.qsize(), "unique_probe_keys": len(self.cache),
                  "elapsed_seconds": round(time.monotonic() - started, 1)})
            print(json.dumps({"utc": utc(), "complete": final, "counts": dict(self.counts), "queued": queue.qsize()}), flush=True)

        async def reporter():
            while True:
                progress()
                await asyncio.sleep(20)

        workers = [asyncio.create_task(worker()) for _ in range(self.args.workers)]
        report = asyncio.create_task(reporter())
        source = Path(self.args.discovery)
        position = 0
        while True:
            if source.exists():
                with source.open() as stream:
                    stream.seek(position)
                    while True:
                        before = stream.tell()
                        line = stream.readline()
                        if not line or not line.endswith("\n"):
                            position = before
                            break
                        position = stream.tell()
                        item = json.loads(line)
                        if item["A"] not in completed and item["outcome"] in ["svcb_answer", "no_svcb_answer"]:
                            completed.add(item["A"])
                            await queue.put(item)
            status = source.parent / "discovery-progress.json"
            if status.exists() and json.loads(status.read_text()).get("complete"):
                if source.exists() and position >= source.stat().st_size:
                    break
            if self.args.no_follow:
                break
            await asyncio.sleep(5)
        await queue.join()
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)
        report.cancel()
        progress(final=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--vantage", required=True)
    parser.add_argument("--timeout", type=float, default=6)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--connections", type=int, default=32)
    parser.add_argument("--no-follow", action="store_true")
    asyncio.run(Survey(parser.parse_args()).run())
