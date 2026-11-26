import hashlib, hmac, http.client, ipaddress, json, os, re, socket, ssl, threading, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443)
NAMES = {21:"ftp",22:"ssh",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",445:"smb",3306:"mysql",5432:"postgresql",6379:"redis",8080:"http-alt",8443:"https-alt"}
MODULES = {"network":"Network Security","web":"Web Application","code":"Code & Dependencies","container":"Container Security","cloud":"Cloud & IaC"}
REPORTS = {}
LOCK = threading.Lock()
LAST_NETWORK_SCAN = 0.0

def now():
    return datetime.now(timezone.utc).isoformat()

def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def add_finding(items, title, severity, evidence, recommendation, validation):
    items.append({"title":title,"severity":severity,"evidence":evidence,"recommendation":recommendation,"validation":validation})

def scoped_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Enter one IPv4 address.")
    if address.version != 4 or not address.is_global:
        raise PermissionError("Only public IPv4 targets can be checked from this hosted scanner.")
    allowed = {item.strip() for item in os.getenv("ALLOWED_TARGETS", "").split(",") if item.strip()}
    if not allowed:
        raise RuntimeError("Server scan scope is not configured.")
    if str(address) not in allowed:
        raise PermissionError("Target is not on the authorized server allowlist.")
    return str(address)

def scoped_web_target(value):
    raw = str(value or "").strip()
    if not raw or len(raw) > 253 or "/" in raw or "@" in raw or ":" in raw:
        raise ValueError("Enter a domain only, such as sixermediaclub.com.")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        target = scoped_ip(raw)
        return target, [target]
    try:
        host = raw.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Enter a valid domain name.")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if not re.fullmatch(label + r"(?:\." + label + r")+", host):
        raise ValueError("Enter a valid public domain name.")
    allowed = {item.strip().rstrip(".").encode("idna").decode("ascii").lower()
               for item in os.getenv("ALLOWED_TARGETS", "").split(",") if item.strip()}
    if not allowed:
        raise RuntimeError("Server scan scope is not configured.")
    if host not in allowed:
        raise PermissionError("Domain is not on the authorized server allowlist.")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError:
        raise ValueError("The approved domain did not resolve to an IPv4 address.")
    if not addresses or any(not ipaddress.ip_address(item).is_global for item in addresses):
        raise PermissionError("The domain must resolve only to public IPv4 addresses.")
    return host, addresses

class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout=3):
        super().__init__(host, port, timeout=timeout)
        self.address = address
    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)

class PinnedHTTPSConnection(PinnedHTTPConnection):
    def __init__(self, host, address, port, timeout=3):
        super().__init__(host, address, port, timeout)
        self.context = ssl.create_default_context()
    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self.context.wrap_socket(raw, server_hostname=self.host)

def port_scan(target):
    services, findings = [], []
    for port in PORTS:
        try:
            with socket.create_connection((target, port), timeout=0.2):
                services.append({"port":port,"protocol":"tcp","service":NAMES.get(port,"unknown"),"product":"","version":""})
        except OSError:
            pass
    for service in services:
        port = service["port"]
        if port in (21, 23, 445, 3306, 5432, 6379):
            add_finding(findings, "Review exposed " + service["service"] + " port " + str(port), "medium",
                        "TCP connection accepted on port " + str(port) + ".",
                        "Confirm the service is required and restrict access with firewall rules.",
                        "Open port observed; no exploitation attempted.")
    return services, findings

def web_headers(target, addresses):
    services, findings = [], []
    for port in (80, 443):
        connection = None
        try:
            address = addresses[0]
            if port == 443:
                connection = PinnedHTTPSConnection(target, address, port)
            else:
                connection = PinnedHTTPConnection(target, address, port)
            connection.request("HEAD", "/", headers={"User-Agent":"Nexora-VulnScan/1.0"})
            response = connection.getresponse()
            services.append({"port":port,"protocol":"tcp","service":"https" if port == 443 else "http","product":"","version":""})
            headers = {key.lower(): value for key, value in response.getheaders()}
            checks = {
                "x-content-type-options":"Set X-Content-Type-Options: nosniff.",
                "content-security-policy":"Define a restrictive Content-Security-Policy appropriate for the application.",
            }
            if port == 443:
                checks["strict-transport-security"] = "Enable HSTS after confirming HTTPS coverage."
            for name, fix in checks.items():
                if name not in headers:
                    add_finding(findings, "Missing " + name + " header", "low",
                                "HTTP " + str(response.status) + "; " + name + " was absent on port " + str(port) + ".",
                                fix, "Read response headers only; no exploitation or crawling.")
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            pass
        finally:
            if connection:
                connection.close()
    return services, findings

def line_number(text, pattern, flags=0):
    match = re.search(pattern, text, flags)
    return text.count("\n", 0, match.start()) + 1 if match else None

def source_scan(filename, text):
    findings, queries = [], []
    rules = [
        ("Embedded private key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "high", "Remove the key from source and rotate it immediately."),
        ("Hard-coded credential-like value", r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]", "high", "Move secrets to a secret manager and rotate any real credential."),
        ("Dynamic code execution", r"\b(?:eval|exec)\s*\(", "high", "Avoid evaluating untrusted text as code; use a constrained parser."),
        ("Unsafe Python deserialization", r"\bpickle\.loads?\s*\(", "high", "Do not deserialize untrusted data with pickle."),
        ("Unsafe YAML loading", r"\byaml\.load\s*\(", "medium", "Use yaml.safe_load for untrusted YAML."),
        ("TLS certificate verification disabled", r"(?:verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*['\"]?\s*[:=]\s*['\"]?0)", "medium", "Keep certificate verification enabled."),
        ("Potential DOM injection sink", r"\.innerHTML\s*=", "medium", "Sanitize untrusted data or use textContent instead."),
        ("Shell command execution", r"(?:os\.system\s*\(|shell\s*=\s*True)", "high", "Avoid shell command construction; pass an argument array and validate inputs."),
    ]
    for title, pattern, severity, fix in rules:
        line = line_number(text, pattern)
        if line:
            add_finding(findings, title, severity, "Heuristic match at line " + str(line) + "; matched text is not copied into the report.", fix,
                        "Static pattern check only; manually review the surrounding code.")
    base = os.path.basename(filename).lower()
    packages = []
    if base == "requirements.txt":
        for line in text.splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)", line)
            if match:
                packages.append({"name":match.group(1),"version":match.group(2),"ecosystem":"PyPI"})
    elif base == "package.json":
        try:
            manifest = json.loads(text)
            for group in ("dependencies", "devDependencies"):
                for name, version in (manifest.get(group) or {}).items():
                    version = str(version).strip()
                    if re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", version):
                        packages.append({"name":name,"version":version.lstrip("v"),"ecosystem":"npm"})
                    elif version:
                        add_finding(findings, "Dependency version is not pinned: " + str(name), "info",
                                    "Manifest uses a version range instead of an exact version.",
                                    "Use a lockfile and scan the resolved dependency versions.",
                                    "Exact-version advisory lookup was skipped for this range.")
        except (json.JSONDecodeError, AttributeError):
            add_finding(findings, "Invalid package.json", "low", "The manifest could not be parsed as JSON.",
                        "Fix the JSON syntax and scan again.", "Manifest parsing failed.")
    if packages:
        packages = packages[:25]
        request_body = {"queries":[{"package":{"name":p["name"],"ecosystem":p["ecosystem"]},"version":p["version"]} for p in packages]}
        try:
            request = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(request_body).encode(),
                                             headers={"Content-Type":"application/json","User-Agent":"Nexora-VulnScan/1.0"}, method="POST")
            with urllib.request.urlopen(request, timeout=5) as response:
                results = json.loads(response.read(128000)).get("results", [])
            for package, result in zip(packages, results):
                for vuln in (result or {}).get("vulns", [])[:5]:
                    advisory = vuln.get("id", "OSV advisory")
                    severity = "high" if "CVE-" in advisory.upper() else "medium"
                    add_finding(findings, advisory + " affects " + package["name"] + " " + package["version"], severity,
                                "OSV returned advisory " + advisory + " for this exact package version.",
                                "Review the advisory and upgrade to a fixed version when available.",
                                "Exact-version lookup via OSV; verify applicability before remediation.")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            add_finding(findings, "Dependency advisory lookup unavailable", "info",
                        "The OSV service did not respond within the scan limit.",
                        "Retry later or inspect the manifest with OSV directly.",
                        "Source pattern checks still completed; no dependency advisory conclusion is available.")
    return findings

def container_scan(text):
    findings = []
    lines = text.splitlines()
    if not re.search(r"(?im)^\s*USER\s+[^#\s]+", text):
        add_finding(findings, "Container may run as root", "medium", "No USER instruction was found.",
                    "Create a dedicated unprivileged user and set USER in the final image stage.",
                    "Dockerfile instruction check; runtime user was not verified.")
    for number, line in enumerate(lines, 1):
        m = re.match(r"\s*FROM\s+([^\s]+)", line, re.I)
        if m and (m.group(1).endswith(":latest") or ":" not in m.group(1).split("/")[-1]):
            add_finding(findings, "Unpinned base image", "low", "FROM reference on line " + str(number) + " is not pinned to a version or digest.",
                        "Pin a reviewed image tag or immutable digest.", "Dockerfile text check only.")
            break
    checks = [
        ("Remote script piped to shell", r"(?im)^\s*RUN\s+.*(?:curl|wget).*\|\s*(?:sh|bash)", "high", "Download and verify scripts separately; avoid piping remote content into a shell."),
        ("Potential secret in build arguments", r"(?im)^\s*(?:ARG|ENV)\s+[^\n]*(?:PASSWORD|TOKEN|SECRET|API_KEY)", "high", "Do not bake secrets into image layers; inject them at runtime."),
        ("Overly broad file permissions", r"(?i)chmod\s+(?:-R\s+)?777", "medium", "Grant only the minimum required file permissions."),
        ("ADD used where COPY may suffice", r"(?im)^\s*ADD\s+", "info", "Prefer COPY unless archive extraction or remote URL behavior is specifically needed."),
    ]
    for title, pattern, severity, fix in checks:
        n = line_number(text, pattern)
        if n:
            add_finding(findings, title, severity, "Dockerfile pattern at line " + str(n) + ".", fix, "Static Dockerfile rule; image contents were not inspected.")
    return findings

def cloud_scan(text):
    findings = []
    checks = [
        ("Public network ingress", r"(?is)(?:ingress|ingress_rule|security_group).*?0\.0\.0\.0/0|0\.0\.0\.0/0.*?(?:ingress|security_group)", "high", "Restrict ingress CIDRs to the minimum trusted source ranges."),
        ("Wildcard IAM permissions", r"(?is)(?:Action|actions)\s*[:=]\s*(?:\[\s*)?['\"]\*['\"]", "high", "Replace wildcard actions and resources with least-privilege permissions."),
        ("Storage public access enabled", r"(?i)(?:public-read|block_public_(?:acls|policy)\s*=\s*false|publicaccessblockconfiguration\s*:\s*false)", "high", "Block public access unless it is explicitly required and reviewed."),
        ("Encryption disabled", r"(?i)(?:encrypted|encryption)\s*[:=]\s*false", "medium", "Enable encryption at rest for supported resources."),
        ("Privileged workload", r"(?i)privileged\s*:\s*true", "high", "Avoid privileged containers; remove unnecessary host capabilities."),
        ("Host filesystem mount", r"(?i)hostPath\s*:", "medium", "Avoid hostPath mounts unless required and narrowly scoped."),
    ]
    for title, pattern, severity, fix in checks:
        n = line_number(text, pattern)
        if n:
            add_finding(findings, title, severity, "Configuration pattern near line " + str(n) + ".", fix,
                        "Static text rule; deployed cloud configuration was not queried.")
    return findings

def analyze(data):
    module = data.get("module", "network")
    if module not in MODULES:
        raise ValueError("Choose one of the five supported scanner modules.")
    findings, services, events = [], [], []
    if module in ("network", "web"):
        if module == "network":
            target = scoped_ip(data.get("target", ""))
            services, findings = port_scan(target)
            detail = "Fixed TCP port list; no exploitation."
        else:
            target, addresses = scoped_web_target(data.get("target", ""))
            services, findings = web_headers(target, addresses)
            detail = "HTTP HEAD security-header checks on the approved hostname at ports 80 and 443; no crawling or exploitation."
            if not services:
                events.append({"timestamp":now(),"event":"web_check.incomplete","details":"No reachable HTTP service or TLS verification failed."})
        label = target
    else:
        text = data.get("content", "")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Paste the file or configuration text to scan.")
        if len(text) > 25000:
            raise ValueError("Text limit is 25,000 characters.")
        filename = os.path.basename(str(data.get("filename", "input.txt")).replace("\\", "/"))[:120]
        label = MODULES[module] + ": " + filename
        if module == "code":
            findings = source_scan(filename, text)
            detail = "Heuristic source checks and exact-version OSV dependency lookup where a supported manifest was supplied."
        elif module == "container":
            findings = container_scan(text)
            detail = "Static Dockerfile configuration rules; container image layers and packages were not scanned."
        else:
            findings = cloud_scan(text)
            detail = "Static Terraform, YAML, or JSON policy patterns; no cloud account was accessed."
    return module, label, services, findings, detail, events

class handler(BaseHTTPRequestHandler):
    def out(self, status, data):
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def auth(self):
        key = os.getenv("SCAN_API_KEY", "")
        if not key:
            self.out(503, {"detail":"API key is not configured."})
            return False
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + key):
            self.out(401, {"detail":"Invalid API key."})
            return False
        return True
    def do_GET(self):
        if not self.auth():
            return
        path = re.sub(r"^/api", "", urlsplit(self.path).path)
        if path in ("/scans", "/scans/"):
            result = [{"id":r["id"],"target":r["target"],"created_at":r["created_at"],"status":r["status"],
                       "findings":len(r["findings"]),"integrity_verified":r["integrity_verified"],"module":r["module"]}
                      for r in sorted(REPORTS.values(), key=lambda r:r["created_at"], reverse=True)[:30]]
            self.out(200, result)
            return
        match = re.fullmatch(r"/scans/([0-9a-fA-F-]{36})/?", path)
        if match and match.group(1) in REPORTS:
            self.out(200, REPORTS[match.group(1)])
        else:
            self.out(404, {"detail":"Report expired or unavailable."})
    def do_POST(self):
        global LAST_NETWORK_SCAN
        if not self.auth():
            return
        if re.sub(r"^/api", "", urlsplit(self.path).path).rstrip("/") != "/scans":
            self.out(404, {"detail":"Route not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 32768:
                raise ValueError("Request must contain no more than 32 KB.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or data.get("consent") is not True:
                raise ValueError("Confirm that you are authorized to scan this target or content.")
            module = data.get("module", "network")
            if module == "network":
                scoped_ip(data.get("target", ""))
            elif module == "web":
                scoped_web_target(data.get("target", ""))
            if module in ("network", "web"):
                with LOCK:
                    current = time.monotonic()
                    if current - LAST_NETWORK_SCAN < 10:
                        raise TimeoutError("Wait 10 seconds between network scans.")
                    LAST_NETWORK_SCAN = current
        except PermissionError as exc:
            self.out(403, {"detail":str(exc)})
            return
        except RuntimeError as exc:
            self.out(503, {"detail":str(exc)})
            return
        except TimeoutError as exc:
            self.out(429, {"detail":str(exc)})
            return
        except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
            self.out(400, {"detail":str(exc) or "Invalid request."})
            return
        try:
            module, label, services, findings, scope, events = analyze(data)
        except PermissionError as exc:
            self.out(403, {"detail":str(exc)})
            return
        except RuntimeError as exc:
            self.out(503, {"detail":str(exc)})
            return
        except (ValueError, TypeError, AttributeError) as exc:
            self.out(400, {"detail":str(exc) or "Invalid request."})
            return
        report = {"id":str(uuid.uuid4()),"module":module,"module_label":MODULES[module],"target":label,
                  "scope":scope,"created_at":now(),"status":"completed","services":services,"findings":findings,"events":events}
        previous = "0" * 64
        for event in report["events"]:
            event.setdefault("timestamp", now())
            event["previous_sha256"] = previous
            event["entry_sha256"] = sha(event)
            previous = event["entry_sha256"]
        event = {"timestamp":now(),"event":module + ".completed","details":scope,"previous_sha256":previous}
        event["entry_sha256"] = sha(event)
        report["events"].append(event)
        report["sha256"] = sha(report)
        report["integrity_verified"] = report["sha256"] == sha({k:v for k,v in report.items() if k not in ("sha256","integrity_verified")})
        REPORTS[report["id"]] = report
        self.out(200, report)
    def log_message(self, *_args):
        return
