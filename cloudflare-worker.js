/* ============================================================
   NewAPI Chat — Cloudflare Worker (CORS proxy)
   ------------------------------------------------------------
   این Worker درخواست‌های اپ را به سرور مقصد فوروارد می‌کند،
   هدرهای CORS را اضافه می‌کند و خود را شبیه یک مرورگر واقعی
   نشان می‌دهد تا شانس عبور از فایروال (WAF) بالا برود.

   استفاده در اپ:
     در فیلد «CORS Proxy» این مقدار را بگذارید:
       https://<your-worker>.workers.dev/?url={url}

   نکته: استریم (چت کلمه‌به‌کلمه) حفظ می‌شود.
   ============================================================ */

// فقط این هاست‌ها اجازه‌ی عبور دارند (برای جلوگیری از سوءاستفاده).
// هاست سرورهای خودت را اینجا اضافه کن. برای آزاد گذاشتن، آرایه را خالی کن: []
const ALLOW_HOSTS = [
  'agentrouter.org',
  'api.bluesminds.com',
];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization,Content-Type',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request) {
    // پاسخ به preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const reqUrl = new URL(request.url);
    const target = reqUrl.searchParams.get('url');
    if (!target) return json({ error: 'missing ?url=' }, 400);

    let t;
    try { t = new URL(target); } catch { return json({ error: 'bad url' }, 400); }
    if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(t.hostname)) {
      return json({ error: 'host not allowed: ' + t.hostname }, 403);
    }

    // ساخت درخواست به سرور مقصد
    const headers = new Headers();
    const auth = request.headers.get('Authorization');
    if (auth) headers.set('Authorization', auth);
    const ct = request.headers.get('Content-Type');
    if (ct) headers.set('Content-Type', ct);
    // شبیه مرورگر واقعی شدن — برای کمک به عبور از WAF
    headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');
    headers.set('Accept', 'application/json, text/event-stream, */*');
    headers.set('Accept-Language', 'en-US,en;q=0.9,fa;q=0.8');
    headers.set('Referer', t.origin + '/');
    headers.set('Origin', t.origin);

    const init = { method: request.method, headers };
    if (request.method === 'POST') init.body = await request.arrayBuffer();

    let resp;
    try {
      resp = await fetch(t.toString(), init);
    } catch (e) {
      return json({ error: 'upstream fetch failed: ' + e.message }, 502);
    }

    // پاسخ را با هدرهای CORS و بدنه‌ی استریم برگردان
    const outHeaders = new Headers(resp.headers);
    for (const [k, v] of Object.entries(CORS)) outHeaders.set(k, v);
    outHeaders.delete('content-security-policy');
    return new Response(resp.body, { status: resp.status, headers: outHeaders });
  }
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
