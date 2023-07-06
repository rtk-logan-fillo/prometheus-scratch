from urllib.parse import urlparse, quote_plus
import ssl
import random
from urllib.request import build_opener, HTTPHandler, HTTPSHandler,Request

from prometheus_client import CollectorRegistry, Gauge, Counter, Enum,  push_to_gateway

################################################################################
# Below is copied from the source code and modified to prevent SSL verification
################################################################################
def default_handler(
        url: str,
        method: str,
        timeout,
        headers,
        data: bytes,
):
    """Default handler that implements HTTP/HTTPS connections.

    Used by the push_to_gateway functions. Can be re-used by other handlers."""

    return _make_handler(url, method, timeout, headers, data, HTTPHandler)

def _make_handler(
        url: str,
        method: str,
        timeout,
        headers,
        data: bytes,
        base_handler
):
    def handle() -> None:
        request = Request(url, data=data, unverifiable=True)
        request.get_method = lambda: method  # type: ignore
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        for k, v in headers:
            request.add_header(k, v)
        resp = build_opener(HTTPSHandler(context=context)).open(request, timeout=timeout)
        if resp.code >= 400:
            raise OSError(f"error talking to pushgateway: {resp.code} {resp.msg}")
    return handle
################################################################################


cids = ['baconsecurity', 'baconsecurity', 'baconsecurity','baconsecurity' ]
dids = ['baconsecurity45', 'baconsecurity45', 'baconsecurity45' , 'baconsecurity67']
ints = ['security_vendor','security_vendor','security_vendor' ,'microsoft']
urls = ['https://api.security.com/api/v1/events', 'https://api.security.com/api/v1/logs', 'https://api.security.com/api/v1/threats' ,'https://api.microsoft.com/api/threats']

codes = [200, 302, 401, 402, 404, 500 ]
codes_perc = [0.80, 0.02, 0.05, 0.05, 0.05,0.03]

cs = random.choices(codes, weights=codes_perc, k=4)
for i in range(4):
    url = urls[i]
    cid = cids[i]
    did = dids[i]
    integration = ints[i]
    code = cs[i]
    o = urlparse(url)
    host = o.hostname
    path = o.path
    elapsed_time = random.random() 
    registry = CollectorRegistry()

    success = (code >= 200) and (code < 300) 
    volume = int(random.random()*100)

    job = f"pollerbear_{quote_plus(url)}_{did}"

    rtt = Gauge('endpoint_rtt', 'Endpoint RTT', ['customer_id', 'deployment_id', 'integration', 'url', 'host', 'path'], registry=registry)
    rtt.labels(cid, did, integration, url, host, path).set(elapsed_time)

    vol = Gauge('endpoint_volume', 'Endpoint Volume', ['customer_id', 'deployment_id', 'integration', 'url', 'host', 'path'], registry=registry)
    vol.labels(cid, did, integration, url, host, path).set(volume)

    suc = Gauge('endpoint_poll_success', 'Endpoint Volume', ['customer_id', 'deployment_id', 'integration', 'url', 'host', 'path'], registry=registry)
    suc.labels(cid, did, integration, url, host, path).set(success)

    http = Enum("endpoint_http_status_code", "Endpoint HTTP Status Codes", ['customer_id', 'deployment_id', 'integration', 'url', 'host', 'path'], registry=registry, states=['200', '302', '401', '402', '404', '500'])
    http.labels(cid, did, integration, url, host, path).state(str(code))

    http2 = Gauge("endpoint_http_status_code2", "Endpoint HTTP Status Codes", ['customer_id', 'deployment_id', 'integration', 'url', 'host', 'path'], registry=registry)
    http2.labels(cid, did, integration, url, host, path).set(code)

    push_to_gateway('https://push.metrik.infra.us001-dev.rtkwlf.io', job=job, registry=registry, handler=default_handler)

print("done")