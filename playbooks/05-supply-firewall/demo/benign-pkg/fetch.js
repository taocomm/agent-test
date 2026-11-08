// benign postinstall:向本机采集器发一个 GET —— 在白名单内应畅通
const http = require('http');
http.get('http://127.0.0.1:8080/', (res) => {
  res.resume();
  console.log('[benign] collector HTTP', res.statusCode);
  process.exit(0);
}).on('error', (e) => {
  console.log('[benign] error:', e.code || String(e));
  process.exit(1);
});
