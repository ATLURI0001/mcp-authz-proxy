#!/usr/bin/env python3
"""Interactive local Authorization Code + PKCE S256 demonstration.
Prints an access token to stdout; diagnostics go to stderr. Do not commit tokens.
"""
import base64, hashlib, http.server, json, secrets, sys, time, urllib.parse, urllib.request, webbrowser
issuer='http://localhost:8082/realms/mcp-demo'
resource='http://localhost:8080/mcp'
redirect='http://127.0.0.1:8765/callback'
verifier=secrets.token_urlsafe(48)
challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
state=secrets.token_urlsafe(32)
with urllib.request.urlopen(issuer+'/.well-known/openid-configuration',timeout=10) as r: meta=json.load(r)
if 'S256' not in meta.get('code_challenge_methods_supported',[]):raise SystemExit('Issuer must advertise S256')
if meta.get('issuer')!=issuer:raise SystemExit('Issuer mismatch')
for field in ['authorization_endpoint','token_endpoint']:
    if not meta[field].startswith(issuer+'/'):raise SystemExit('Unexpected endpoint')
received={}
class Callback(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        parsed=urllib.parse.urlsplit(self.path)
        q=urllib.parse.parse_qs(parsed.query)
        if parsed.path!='/callback' or q.get('state')!=[state]:
            self.send_error(400,'Invalid OAuth state');return
        if 'code' not in q:
            self.send_error(400,'Authorization denied');received['error']=True;return
        received['code']=q['code'][0]
        self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers();self.wfile.write(b'Login complete. Return to your terminal.')
url=meta['authorization_endpoint']+'?'+urllib.parse.urlencode({'client_id':'mcp-demo-cli','response_type':'code','redirect_uri':redirect,'scope':'mcp:connect tools:read tools:write','state':state,'code_challenge':challenge,'code_challenge_method':'S256','resource':resource})
with http.server.HTTPServer(('127.0.0.1',8765),Callback) as server:
    server.timeout=1
    print('Open this URL to sign in:\n'+url,file=sys.stderr);webbrowser.open(url)
    deadline=time.monotonic()+180
    while not received and time.monotonic()<deadline:server.handle_request()
if 'code' not in received:raise SystemExit('Login failed or timed out')
data=urllib.parse.urlencode({'grant_type':'authorization_code','client_id':'mcp-demo-cli','code':received['code'],'redirect_uri':redirect,'code_verifier':verifier,'resource':resource}).encode()
with urllib.request.urlopen(urllib.request.Request(meta['token_endpoint'],data=data,headers={'Content-Type':'application/x-www-form-urlencoded'}),timeout=10) as r:print(json.load(r)['access_token'])
