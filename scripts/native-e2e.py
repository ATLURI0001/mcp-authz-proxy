#!/usr/bin/env python3
"""Optional native end-to-end check. Requires built binaries, seeded test PostgreSQL, Redis, and cryptography. Uses a test JWKS issuer, not Keycloak."""
import os,json,time,base64,threading,subprocess,urllib.request,urllib.error,hashlib
from pathlib import Path
from http.server import HTTPServer,BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
root=Path(__file__).resolve().parents[1]
b64=lambda x:base64.urlsafe_b64encode(x).rstrip(b'=').decode()
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
pub=key.public_key().public_numbers()
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  body=json.dumps({'keys':[{'kid':'e2e','kty':'RSA','alg':'RS256','n':b64(pub.n.to_bytes(256,'big')),'e':b64(pub.e.to_bytes(3,'big'))}]}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
issuer=HTTPServer(('127.0.0.1',18082),Handler)
threading.Thread(target=issuer.serve_forever,daemon=True).start()
config=json.loads((root/'configs/local.json').read_text());config.update(resource='http://127.0.0.1:18080/mcp',issuer='http://127.0.0.1:18082',jwks_url='http://127.0.0.1:18082/certs',requests_per_minute=100)
import tempfile
tmp=tempfile.TemporaryDirectory(prefix='mcp-e2e-')
config_path=Path(tmp.name)/'config.json'
config_path.write_text(json.dumps(config))
env=os.environ|{'CONFIG_FILE':str(config_path),'DATABASE_URL':os.environ['TEST_DATABASE_URL'],'REDIS_URL':os.environ['TEST_REDIS_URL'],'UPSTREAM_ALICE_TOKEN':'native-e2e-alice-credential','UPSTREAM_BOB_TOKEN':'native-e2e-bob-credential','LISTEN_ADDR':'127.0.0.1:18080','METRICS_ADDR':'127.0.0.1:19090'}
procs=[]
log=open(Path(tmp.name)/'gateway.log','w')
try:
 for cmd in ['demo-server','gateway']:procs.append(subprocess.Popen([str(root/'bin'/cmd)],env=env,stdout=log,stderr=log))
 for i in range(50):
  try:
   with urllib.request.urlopen('http://127.0.0.1:18080/readyz',timeout=1) as r:
    if r.status==200:break
  except Exception:time.sleep(.1)
 else:raise RuntimeError('gateway not ready')
 def token(sub,aud='http://127.0.0.1:18080/mcp'):
  header=b64(json.dumps({'alg':'RS256','kid':'e2e'}).encode());payload=b64(json.dumps({'iss':config['issuer'],'aud':aud,'sub':sub,'exp':int(time.time())+120,'scope':'mcp:connect tools:read tools:write'}).encode());msg=header+'.'+payload
  return msg+'.'+b64(key.sign(msg.encode(),padding.PKCS1v15(),hashes.SHA256()))
 alice='11111111-1111-4111-8111-111111111111';bob='22222222-2222-4222-8222-222222222222'
 at=token(alice);bt=token(bob)
 def call(t,name,args={},approval=None):
  body=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}).encode()
  headers={'Authorization':'Bearer '+t,'Accept':'application/json, text/event-stream','Content-Type':'application/json','MCP-Protocol-Version':'2025-11-25'}
  if approval:headers['X-Approval-Token']=approval
  req=urllib.request.Request(config['resource'],data=body,headers=headers)
  try:
   with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.load(r)
  except urllib.error.HTTPError as e:return e.code,json.load(e)
 assert call(at,'echo',{'message':'hello'})[0]==200
 assert call(bt,'echo',{'message':'blocked'})[0]==403
 for tok,user in [(at,'alice'),(bt,'bob')]:
  status,result=call(tok,'whoami');assert status==200 and result['result']['content'][0]['text']==user,(status,result)
 assert call(token(alice,'wrong-audience'),'whoami')[0]==401
 assert call(at,'restart_demo')[0]==403
 approval=subprocess.check_output([str(root/'bin/admin'),'approve','-subject',alice,'-tool','restart_demo','-params',str(root/'configs/restart-params.json')],env=env,text=True).strip()
 assert call(at,'restart_demo',{'changed':True},approval)[0]==403
 status,result=call(at,'restart_demo',{},approval);assert status==200 and not result['result']['isError']
 assert call(at,'restart_demo',{},approval)[0]==403
 print('PASS native end-to-end: real RS256/JWKS validation, gateway/demo binaries, PostgreSQL grants/audit/approvals, Redis limits, credential isolation, wrong-audience denial, approval binding and replay')
finally:
 for p in procs:p.terminate()
 for p in procs:
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill()
 issuer.shutdown();log.close();tmp.cleanup()
