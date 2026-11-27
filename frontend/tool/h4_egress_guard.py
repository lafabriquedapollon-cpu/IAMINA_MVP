"""Scoped qualification guard. Not a production sandbox or a native network firewall."""
from urllib.parse import unquote, urlsplit


def static_request_allowed(request, allowed):
    # Never permit a mutation, an API route (including encoded spelling), or
    # an origin lookalike. Browser URLs are already normalized in most cases.
    if request.method not in ("GET", "HEAD"):
        return False
    try:
        url = urlsplit(request.url)
        if url.scheme not in ("http", "https") or url.username or url.password:
            return False
        path = unquote(url.path).replace("\\", "/").lower()
        if "%" in path or any(part in ("api", "..", ".") for part in path.split("/")):
            return False
        return any((url.scheme, url.netloc) == (urlsplit(o).scheme, urlsplit(o).netloc)
                   for o in allowed)
    except (ValueError, UnicodeError):
        return False


DIRECT_GUARD = r"""(() => {
  if(typeof globalThis.ServiceWorkerContainer?.prototype?.register==='function'){
    Object.defineProperty(globalThis.ServiceWorkerContainer.prototype,'register',{
      value:function(){
        if(typeof globalThis.__h4ReportTransport==='function'){
          Promise.resolve(globalThis.__h4ReportTransport('ServiceWorker.register')).catch(()=>{});
        }
        return Promise.reject(new DOMException('H4 service worker refused','SecurityError'));
      },writable:false,configurable:false
    });
  }
  const names=['RTCPeerConnection','webkitRTCPeerConnection','WebTransport'];
  for(const name of names){
    if(typeof globalThis[name]!=='function')continue;
    // Do not call the native constructor; no ICE/QUIC negotiation is initiated.
    const refuse=function(){
      if(typeof globalThis.__h4ReportTransport==='function'){
        Promise.resolve(globalThis.__h4ReportTransport(name)).catch(()=>{});
      }
      throw new DOMException('H4 transport refused','SecurityError');
    };
    Object.defineProperty(globalThis,name,{value:refuse,writable:false,configurable:false});
  }
})();"""


def attach_direct_transport_guard(context, blocked):
    allowed = {"RTCPeerConnection", "webkitRTCPeerConnection", "WebTransport", "ServiceWorker.register"}
    def report(_source, name):
        blocked.append("direct_transport:" + (name if isinstance(name,str) and name in allowed else "unknown"))
    context.expose_binding("__h4ReportTransport", report)
    context.add_init_script(DIRECT_GUARD)
