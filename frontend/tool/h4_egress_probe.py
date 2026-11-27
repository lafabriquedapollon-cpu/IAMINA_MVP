"""H4 R4: loopback witnesses, positive controls, separate real negative attempts.

The guard covers the tested browser documents and routable requests. No real
patient data, no external host, no claim of native process/worker UDP isolation.
"""
import http.server
import threading
from urllib.parse import urlsplit
from contextlib import ExitStack
from playwright.sync_api import sync_playwright
from h4_egress_guard import attach_direct_transport_guard, static_request_allowed, service_worker_script_request
from h4_websocket_guard import attach_websocket_guard


def policy_cases():
    class Req:
        def __init__(self, method, url):
            self.method, self.url = method, url
    origin = "http://127.0.0.1:12345"
    cases = [
        ("GET", origin+"/ok", True), ("HEAD", origin+"/ok", True),
        ("GET", origin+"/assets/a.js?v=1", True),
        ("POST", origin+"/ok", False), ("PUT", origin+"/ok", False),
        ("GET", origin+"/api", False), ("GET", origin+"/API/x", False),
        ("GET", origin+"/%61pi/x", False), ("GET", origin+"/%2561pi/x", False),
        ("GET", origin+"/x/../api/x", False),
        ("GET", origin+"@example.invalid/x", False),
        ("GET", "http://127.0.0.1:12346/ok", False),
        ("GET", "https://127.0.0.1:12345/ok", False),
        ("GET", "data:text/plain,test", False),
    ]
    for method,url,expected in cases:
        assert static_request_allowed(Req(method,url),(origin,)) == expected, (method,url)
    return len(cases)


def exercise_egress(engine):
    hits=[]
    class Witness(http.server.BaseHTTPRequestHandler):
        def respond(self, content=b"ok", kind="text/plain", csp=None):
            self.send_response(200)
            self.send_header("Content-Type",kind)
            self.send_header("Access-Control-Allow-Origin","*")
            self.send_header("Cache-Control","no-store")
            if csp is not None:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(content)
        def do_GET(self):
            hits.append(("GET",self.path))
            if self.path=="/fixture":
                self.respond(b"<!doctype html><title>H4 synthetic</title>","text/html")
            elif self.path=="/fixture-sw-csp":
                self.respond(b"<!doctype html><title>H4 SW CSP negative</title>","text/html", "worker-src 'none'")
            elif self.path=="/worker.js":
                self.respond(b"onmessage=async e=>{try{const r=await fetch(e.data);postMessage(r.ok?'ok':'bad')}catch(_){postMessage('refused')}}","application/javascript")
            elif urlsplit(self.path).path=="/sw.js":
                self.respond(b"self.addEventListener('install',()=>self.skipWaiting());","application/javascript")
            elif urlsplit(self.path).path=="/service-worker.js":
                assert service_worker_script_request(self.path,self.headers)
                hits.append(("SW_DENY",self.path))
                self.send_error(403)
            else:
                self.respond()
        def do_POST(self):
            hits.append(("POST",self.path))
            size=int(self.headers.get("Content-Length","0"))
            assert size<=128
            self.rfile.read(size)
            self.respond()
        def log_message(self,*_):
            pass

    def wait_for(page, predicate, message):
        for _ in range(40):
            if predicate():
                return
            page.wait_for_timeout(100)
        assert predicate(), message

    with ExitStack() as stack:
        a=stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1",0),Witness))
        b=stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1",0),Witness))
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (a,b)]
        for t in threads:
            t.start()
        origin=f"http://127.0.0.1:{a.server_port}"
        upstream=f"http://127.0.0.1:{b.server_port}"
        worker_js="""url=>new Promise(resolve=>{
          const worker=new Worker('/worker.js');
          const done=value=>{worker.terminate();resolve(value)};
          worker.onmessage=e=>done(e.data);
          worker.onerror=()=>done('worker-error');
          worker.postMessage(url);
          setTimeout(()=>done('timeout'),4000);
        })"""
        sw_js="""async path=>{
          if(!navigator.serviceWorker)return 'unavailable';
          return await Promise.race([
            navigator.serviceWorker.register(path).then(()=> 'registered',e=> {
              console.info('H4_SW_REGISTER_ERROR '+e.name);
              return e.name==='SecurityError'&&e.message==='H4 service worker refused'?'guard-refused':'refused';
            }),
            new Promise(r=>setTimeout(()=>r('pending'),2500))
          ]);
        }"""
        records=[]
        try:
            with sync_playwright() as pw:
                browser=getattr(pw,engine).launch(headless=True)
                try:
                    # Positive controls show that the witness and the actual
                    # browser APIs can succeed without the qualification guard.
                    positive=browser.new_context(service_workers="allow")
                    try:
                        page=positive.new_page()
                        assert page.goto(origin+"/fixture").status==200
                        capabilities=page.evaluate("""()=>({
                          beacon:typeof navigator.sendBeacon==='function',
                          worker:typeof Worker==='function',
                          serviceWorker:!!navigator.serviceWorker,
                          transports:Object.fromEntries(['RTCPeerConnection','webkitRTCPeerConnection','WebTransport'].map(n=>[n,typeof globalThis[n]==='function']))
                        })""")
                        assert capabilities["beacon"] and capabilities["worker"]
                        assert page.evaluate("url=>navigator.sendBeacon(url,'H4_SYNTHETIC')",upstream+"/beacon-positive")
                        wait_for(page,lambda:("POST","/beacon-positive") in hits,"Beacon witness unavailable")
                        assert page.evaluate(worker_js,upstream+"/worker-positive")=="ok"
                        assert ("GET","/worker-positive") in hits
                        page.on("console",lambda msg: print(msg.text,flush=True)
                                if msg.text.startswith("H4_SW_REGISTER_ERROR ") else None)
                        if capabilities["serviceWorker"]:
                            # Independent MIME check, distinct URL from the actual registration.
                            mime=page.evaluate("""async()=> {
                              const r=await fetch('/sw.js?mime-check');
                              return {status:r.status,mime:r.headers.get('content-type'),
                                      script:(await r.text()).includes('self.skipWaiting()')};
                            }""")
                            assert mime=={"status":200,"mime":"application/javascript","script":True},mime
                            assert ("GET","/sw.js?mime-check") in hits
                        sw_positive=page.evaluate(sw_js,"/sw.js?positive") if capabilities["serviceWorker"] else "unavailable"
                        print("H4_SW_POSITIVE "+engine+" "+sw_positive,flush=True)
                        if capabilities["serviceWorker"]:
                            assert sw_positive=="registered", sw_positive
                            assert ("GET","/sw.js?positive") in hits
                    finally:
                        positive.close()
                    # Independent native negatives in synthetic loopback contexts.
                    # Distinguish browser CSP from server rejection.
                    if capabilities["serviceWorker"]:
                        for mode in ("csp","server"):
                            before=len(hits)
                            control=browser.new_context(service_workers="allow")
                            try:
                                page=control.new_page()
                                fixture="/fixture-sw-csp" if mode=="csp" else "/fixture"
                                response=page.goto(origin+fixture)
                                assert response.status==200
                                if mode=="csp":
                                    assert response.headers.get("content-security-policy")=="worker-src 'none'"
                                path="/sw.js?csp-negative" if mode=="csp" else "/service-worker.js?server-negative"
                                status=page.evaluate(sw_js,path)
                                assert status=="refused",(mode,status)
                                registrations=page.evaluate("async()=> (await navigator.serviceWorker.getRegistrations()).length")
                                assert registrations==0,registrations
                                assert page.evaluate("()=>navigator.serviceWorker.controller===null")
                                page.wait_for_timeout(300)
                            finally:
                                control.close()
                            observed=hits[before:]
                            if mode=="csp":
                                assert ("GET",path) not in observed,observed
                            else:
                                assert observed.count(("GET",path))==1,observed
                                assert observed.count(("SW_DENY",path))==1,observed
                            records.append({"case":"service-worker-"+mode,"positive":sw_positive,
                                "negative":"refused","registrations":0,"controller":False,
                                "scriptRequests":observed.count(("GET",path)),
                                "serverDenials":observed.count(("SW_DENY",path)),
                                "scriptDelivered":False})
                            print("H4_SW_INDEPENDENT "+engine+" "+str(records[-1]),flush=True)
                    else:
                        records.extend({"case":"service-worker-"+mode,"result":"UNAVAILABLE"} for mode in ("csp","server"))
                    # Use a fresh context per negative to prevent false positives
                    # caused by a prior failure or existing service worker.
                    for case in ("beacon","worker","direct-transports"):
                        blocked=[]
                        context=browser.new_context(service_workers="block")
                        before=len(hits)
                        def route(r):
                            if static_request_allowed(r.request,(origin,)):
                                r.continue_()
                            else:
                                blocked.append("http:"+r.request.method+":"+r.request.url.rsplit("/",1)[-1])
                                r.abort()
                        context.route("**/*",route)
                        attach_websocket_guard(context,blocked)
                        attach_direct_transport_guard(context,blocked)
                        try:
                            page=context.new_page()
                            assert page.goto(origin+"/fixture").status==200
                            assert not blocked
                            if case=="beacon":
                                assert page.evaluate("url=>navigator.sendBeacon(url,'H4_SYNTHETIC')",origin+"/beacon-negative")
                                wait_for(page,lambda:bool(blocked),"Beacon attempt not intercepted")
                                assert blocked==["http:POST:beacon-negative"],blocked
                                assert ("POST","/beacon-negative") not in hits[before:]
                                record={"case":case,"positive":"witness-hit","negative":"refused","upstreamHits":0}
                            elif case=="worker":
                                assert page.evaluate(worker_js,upstream+"/worker-negative")=="refused"
                                assert blocked==["http:GET:worker-negative"],blocked
                                assert ("GET","/worker.js") in hits[before:]
                                assert ("GET","/worker-negative") not in hits[before:]
                                record={"case":case,"positive":"witness-hit","negative":"refused","upstreamHits":0}
                            else:
                                observed=page.evaluate("""names=>{
                                  const rows=[];
                                  for(const name of names){
                                    if(typeof globalThis[name]!=='function'){rows.push({name,status:'UNAVAILABLE'});continue}
                                    try{new globalThis[name]();rows.push({name,status:'ACCEPTED'})}
                                    catch(e){rows.push({name,status:e.name==='SecurityError'&&e.message==='H4 transport refused'?'REFUSED':'WRONG_ERROR'})}
                                  }
                                  return rows;
                                }""",list(capabilities["transports"]))
                                expected=["direct_transport:"+n for n,supported in capabilities["transports"].items() if supported]
                                assert expected,"Neither direct transport API exposed"
                                wait_for(page,lambda:len(blocked)>=len(expected),"Transport attempt not recorded")
                                assert sorted(blocked)==sorted(expected),blocked
                                assert all(row["status"]==("REFUSED" if capabilities["transports"][row["name"]] else "UNAVAILABLE") for row in observed),observed
                                record={"case":case,"observed":observed,"scope":"document constructors only; no native UDP or worker transport assertion"}
                            page.wait_for_timeout(300)
                            records.append({**record,"attempts":list(blocked)})
                            print("H4_EGRESS_CASE "+engine+" "+case+" "+str(records[-1]),flush=True)
                        finally:
                            context.close()
                        assert blocked==records[-1]["attempts"],"Late unexpected attempt"
                        assert not any("negative" in p for _,p in hits[before:]),"Forbidden request reached witness"
                finally:
                    browser.close()
        finally:
            a.shutdown()
            b.shutdown()
            for t in threads:
                t.join(timeout=5)
    assert len(records)==5
    return {"policyCases":policy_cases(),"capabilities":capabilities,"cases":records,
            "limits":["document transport guard is not native network isolation",
                      "dedicated worker fetch tested; direct transport constructors in worker realms not covered",
                      "SW native CSP negative and independent static-server 403; browser context and JS guard alone failed R5/R6; PWA lifecycle not qualified",
                      "no proof of absent DNS, speculative traffic, browser process or extension egress"]}
