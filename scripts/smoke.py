#!/usr/bin/env python3
"""Local demo only: password grant avoids a browser in CI. Never use it in production."""
import subprocess
import json, time, urllib.request, urllib.parse, urllib.error
BASE='http://localhost:8080'
def request(url,body=None,headers=None):
    req=urllib.request.Request(url,data=body,headers=headers or {})
    try:
        with urllib.request.urlopen(req,timeout=10) as r:return r.status,r.read()
    except urllib.error.HTTPError as e:return e.code,e.read()
def token(user):
    data=urllib.parse.urlencode({'grant_type':'password','client_id':'mcp-demo-cli','username':user,'password':'demo-'+user+'-local-only','scope':'mcp:connect tools:read tools:write','resource':BASE+'/mcp'}).encode()
    status,body=request('http://localhost:8082/realms/mcp-demo/protocol/openid-connect/token',data,{'Content-Type':'application/x-www-form-urlencoded'})
    assert status==200,(status,body)
    return json.loads(body)['access_token']
def rpc(t,method,params=None,extra=None):
    headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'}
    if t:headers['Authorization']='Bearer '+t
    if extra:headers.update(extra)
    body={'jsonrpc':'2.0','id':1,'method':method}
    if params is not None:body['params']=params
    status,data=request(BASE+'/mcp',json.dumps(body).encode(),headers)
    return status,json.loads(data)
def main():
    for i in range(90):
        try:
            if request(BASE+'/readyz')[0]==200:
                alice=token('alice');break
        except (AssertionError,urllib.error.URLError,TimeoutError):pass
        time.sleep(2)
    else:raise SystemExit('Demo did not become ready within 180 seconds')
    bob=token('bob')
    assert rpc(None,'tools/list')[0]==401
    status,body=rpc(alice,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'smoke','version':'1'}})
    assert status==200 and body['result']['protocolVersion']=='2025-11-25'
    status,body=rpc(alice,'tools/call',{'name':'echo','arguments':{'message':'hello'}})
    assert status==200 and body['result']['content'][0]['text']=='hello'
    assert rpc(bob,'tools/call',{'name':'echo','arguments':{'message':'blocked'}})[0]==403
    for t,name in [(alice,'alice'),(bob,'bob')]:
        status,body=rpc(t,'tools/call',{'name':'whoami','arguments':{}})
        assert status==200 and body['result']['content'][0]['text']==name
    status,body=rpc(bob,'tools/list')
    assert status==200 and [t['name'] for t in body['result']['tools']]==['whoami']
    assert rpc(alice,'tools/call',{'name':'restart_demo','arguments':{}})[0]==403
    approval=subprocess.check_output(['docker','compose','exec','-T','gateway','admin','approve','-subject','11111111-1111-4111-8111-111111111111','-tool','restart_demo','-params','/app/configs/restart-params.json'],text=True).strip()
    headers={'X-Approval-Token':approval}
    assert rpc(alice,'tools/call',{'name':'restart_demo','arguments':{'changed':True}},headers)[0]==403
    status,body=rpc(alice,'tools/call',{'name':'restart_demo','arguments':{}},headers)
    assert status==200 and body['result']['isError'] is False
    assert rpc(alice,'tools/call',{'name':'restart_demo','arguments':{}},headers)[0]==403
    assert rpc(alice,'resources/list')[0]==400
    assert rpc(alice,'tools/list',extra={'Origin':'https://attacker.invalid'})[0]==403
    audit=subprocess.check_output(['docker','compose','exec','-T','postgres','psql','-U','mcp','-d','mcp','-tAc',"SELECT count(DISTINCT event->>'decision') FROM audit_events WHERE event->>'decision' IN ('allow','deny','complete')"],text=True).strip()
    assert audit=='3', 'Expected allow, deny and complete audit events'
    print('PASS: authentication, initialize, forwarding, policy denial, credential isolation, filtered discovery, approval gate, argument binding, single-use execution, durable audit, method and origin restrictions')
if __name__=='__main__':main()
