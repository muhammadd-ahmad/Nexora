import hashlib,hmac,ipaddress,json,os,re,socket,time,uuid
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit
from datetime import datetime,timezone
PORTS=(21,22,25,53,80,110,143,443,445,3306,5432,6379,8080,8443)
NAMES={21:"ftp",22:"ssh",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",445:"smb",3306:"mysql",5432:"postgresql",6379:"redis",8080:"http-alt",8443:"https-alt"}
REPORTS={}; LAST=0.0
def now(): return datetime.now(timezone.utc).isoformat()
def sha(x): return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
def target_ok(value):
 try: ip=ipaddress.ip_address(value)
 except ValueError: raise ValueError("Enter one IPv4 address.")
 if ip.version!=4 or not ip.is_global: raise PermissionError("Only public IPv4 targets can be checked from this hosted scanner.")
 allowed={x.strip() for x in os.getenv("ALLOWED_TARGETS","").split(",") if x.strip()}
 if not allowed: raise RuntimeError("Server scan scope is not configured.")
 if str(ip) not in allowed: raise PermissionError("Target is not on the authorized server allowlist.")
 return str(ip)
def check(ip):
 services=[]; findings=[]
 for p in PORTS:
  try:
   with socket.create_connection((ip,p),timeout=.2): services.append({"port":p,"protocol":"tcp","service":NAMES.get(p,"unknown"),"product":"","version":""})
  except OSError: pass
 for s in services:
  if s["port"] in (21,23,445,3306,5432,6379):
   findings.append({"title":"Review exposed "+s["service"]+" port "+str(s["port"]),"severity":"medium","evidence":"TCP connection accepted on port "+str(s["port"])+".","recommendation":"Confirm the service is required and restrict it with firewall rules.","validation":"Open port observed; no exploitation attempted."})
 return services,findings
class handler(BaseHTTPRequestHandler):
 def out(self,status,data):
  b=json.dumps(data,separators=(",",":"),ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
 def auth(self):
  key=os.getenv("SCAN_API_KEY","")
  if not key: self.out(503,{"detail":"API key is not configured."}); return False
  if not hmac.compare_digest(self.headers.get("Authorization",""),"Bearer "+key): self.out(401,{"detail":"Invalid API key."}); return False
  return True
 def do_GET(self):
  if not self.auth(): return
  path=re.sub(r"^/api","",urlsplit(self.path).path)
  if path in ("/scans","/scans/"):
   self.out(200,[{"id":r["id"],"target":r["target"],"created_at":r["created_at"],"status":r["status"],"findings":len(r["findings"]),"integrity_verified":r["integrity_verified"]} for r in sorted(REPORTS.values(),key=lambda r:r["created_at"],reverse=True)[:30]]); return
  m=re.fullmatch(r"/scans/([0-9a-fA-F-]{36})/?",path)
  self.out(200,REPORTS[m.group(1)]) if m and m.group(1) in REPORTS else self.out(404,{"detail":"Report expired or unavailable."})
 def do_POST(self):
  global LAST
  if not self.auth(): return
  if re.sub(r"^/api","",urlsplit(self.path).path).rstrip("/")!="/scans": self.out(404,{"detail":"Route not found."}); return
  try:
   n=int(self.headers.get("Content-Length","0"))
   if n<1 or n>4096: raise ValueError("Invalid request body.")
   data=json.loads(self.rfile.read(n))
   if not isinstance(data,dict) or data.get("consent") is not True: raise ValueError("Confirm authorization before scanning.")
   ip=target_ok(data.get("target",""))
  except PermissionError as e: self.out(403,{"detail":str(e)}); return
  except RuntimeError as e: self.out(503,{"detail":str(e)}); return
  except (ValueError,TypeError,AttributeError) as e: self.out(400,{"detail":str(e) or "Invalid request."}); return
  if time.monotonic()-LAST<10: self.out(429,{"detail":"Wait 10 seconds between scans."}); return
  LAST=time.monotonic()
  services,findings=check(ip)
  report={"id":str(uuid.uuid4()),"target":ip,"created_at":now(),"status":"completed","services":services,"findings":findings,"events":[]}
  event={"timestamp":now(),"event":"tcp_check.completed","details":"Fixed list of TCP ports; no exploitation.","previous_sha256":"0"*64}
  event["entry_sha256"]=sha(event); report["events"].append(event)
  report["sha256"]=sha(report)
  report["integrity_verified"]=report["sha256"]==sha({k:v for k,v in report.items() if k not in ("sha256","integrity_verified")})
  REPORTS[report["id"]]=report; self.out(200,report)
 def log_message(self,*args): pass
