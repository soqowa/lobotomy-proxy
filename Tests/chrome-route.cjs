// Run with playwright-core available to Node. Use an isolated Chromium to avoid changing existing browser policies.
const { chromium } = require('playwright-core');
const { execFileSync } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const assert = require('node:assert/strict');

function generatedSettings(binary, fixed) {
  const id = 'com.google.Chrome';
  const profile = execFileSync(binary, ['--export-profile'], { input: JSON.stringify({
    domains: ['protected.example.test'], applications: fixed ? [{ id, all: true, domains: [] }] : []
  }) });
  return JSON.parse(execFileSync('python3', ['-c',
    'import plistlib,sys,json; d=plistlib.loads(sys.stdin.buffer.read()); print(json.dumps(next(p["PayloadContent"][sys.argv[1]] for p in d["PayloadContent"] if sys.argv[1] in p["PayloadContent"])["Forced"][0]["mcx_preference_settings"]["ProxySettings"]))', id
  ], { input: profile }));
}
async function listen(server) {
  await new Promise((resolve,reject) => server.once('error',reject).listen(0,'127.0.0.1',resolve));
  return server.address().port;
}
async function main() {
  const binary = path.resolve(process.argv[2] || '../Deliverables/Lobotomy Proxy.app/Contents/MacOS/LobotomyProxy');
  const hits = new Set();
  const origin = http.createServer((req,res) => { hits.add(req.url); res.end('origin'); });
  const port = await listen(origin);
  const unused = net.createServer();
  const off = await listen(unused);
  await new Promise(resolve => unused.close(resolve));
  try {
    const pac = generatedSettings(binary,false), fixed = generatedSettings(binary,true);
    assert.equal(pac.ProxyPacMandatory,true);
    assert.equal(fixed.ProxyMode,'fixed_servers');
    assert.equal(fixed.ProxyBypassList,'<-loopback>');
    // Redirect only the loopback fixture port so the user's real macOS filter can stay up.
    const script = Buffer.from(pac.ProxyPacUrl.split(',')[1],'base64').toString();
    assert.ok(script.includes('PROXY 127.0.0.1:17687'));
    const pacData = Buffer.from(script.replaceAll('127.0.0.1:17687','127.0.0.1:'+off)).toString('base64');
    const argsByMode = {
      baseline: '--no-proxy-server',
      domains: '--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,'+pacData,
      application: '--proxy-server='+fixed.ProxyServer.replace(/:\d+$/,':'+off)
    };
    for (const [mode, flag] of Object.entries(argsByMode)) {
      const browser = await chromium.launch({ channel: 'chromium', executablePath: process.env.PG_TEST_CHROMIUM || undefined, args: [
        '--disable-background-networking','--host-resolver-rules=MAP *.example.test 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost',flag
      ]});
      try {
        for (const host of ['ordinary.example.test','api.protected.example.test','almostprotected.example.test']) {
          const page = await browser.newPage();
          const pathname = '/'+mode+'/'+host;
          let delivered = false;
          try { const r = await page.goto('http://'+host+':'+port+pathname,{timeout:6000}); delivered=(await r.text())==='origin'; }
          catch (e) { if (!/ERR_PROXY_CONNECTION_FAILED|ERR_TUNNEL_CONNECTION_FAILED/.test(String(e))) throw e; }
          const expected = mode==='baseline' || (mode==='domains' && host!=='api.protected.example.test');
          assert.equal(delivered,expected,pathname);
          assert.equal(hits.has(pathname),expected,'direct connection '+pathname);
          console.log(pathname,delivered?'direct':'blocked; zero origin requests');
          await page.close();
        }
      } finally { await browser.close(); }
    }
  } finally { origin.close(); }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
