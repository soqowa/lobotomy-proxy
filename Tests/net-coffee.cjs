// Exercise the exported Chromium preferences with a disposable browser profile.
// No host-resolver overrides. A numeric STUN fixture checks for UDP before visiting the real site.
const {chromium} = require('playwright-core');
const {execFileSync} = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const dgram = require('node:dgram');
const assert = require('node:assert/strict');
async function testUdp(page) {
  const socket = dgram.createSocket('udp4');
  await new Promise(r=>socket.bind(0,'127.0.0.1',r));
  let packets = 0;
  socket.on('message',()=>packets++);
  try {
    await page.evaluate(async port=>{
      const pc = new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:'+port}]});
      try {
        pc.createDataChannel('probe');
        await pc.setLocalDescription(await pc.createOffer());
        await new Promise(r=>setTimeout(r,2400));
      } finally {pc.close();}
    },socket.address().port);
    assert.equal(packets,0,'Direct STUN traffic detected');
    console.log('Numeric STUN endpoint: zero direct UDP packets');
  } finally {socket.close();}
}
async function run() {
  const proxy = new URL(process.env.PG_DIAGNOSTIC_PROXY);
  if(proxy.protocol!=='http:' || proxy.hostname!=='127.0.0.1' || !proxy.port) throw Error('Expected a loopback filter endpoint');
  const city = process.env.PG_TEST_DNS_CITY;
  const country = process.env.PG_TEST_DNS_COUNTRY;
  assert.ok(city && country, 'Set the expected resolver city and country');
  const binary=path.resolve(process.argv[2] || '../Deliverables/Lobotomy Proxy.app/Contents/MacOS/LobotomyProxy');
  const domainMode = process.env.PG_TEST_PAC === '1';
  const profile=execFileSync(binary,['--export-profile'],{input:JSON.stringify({domains:[],applications:domainMode ? [] : [{id:'com.google.Chrome',all:true,domains:[]}]})});
  const settings=JSON.parse(execFileSync('python3',['-c','import plistlib,sys,json; p=plistlib.loads(sys.stdin.buffer.read()); print(json.dumps(next(s["PayloadContent"]["com.google.Chrome"]["Forced"][0]["mcx_preference_settings"] for s in p["PayloadContent"] if "com.google.Chrome" in s["PayloadContent"])))'],{input:profile}));
  let proxyArgs;
  if (domainMode) {
    assert.equal(settings.ProxySettings.ProxyMode,'pac_script');
    const script = Buffer.from(settings.ProxySettings.ProxyPacUrl.split(',')[1],'base64').toString();
    const pac = Buffer.from(script.replaceAll('127.0.0.1:17687',proxy.host)).toString('base64');
    proxyArgs=['--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,' + pac];
  } else {
    assert.equal(settings.ProxySettings.ProxyMode,'fixed_servers');
    proxyArgs=['--proxy-server='+proxy.origin,'--proxy-bypass-list='+settings.ProxySettings.ProxyBypassList];
  }
  assert.equal(settings.QuicAllowed,false);
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'proxyguard-netcoffee-'));
  let browser;
  try {
    fs.mkdirSync(path.join(dir,'Default'));
    fs.writeFileSync(path.join(dir,'Default','Preferences'),JSON.stringify({
      webrtc:{ip_handling_policy:settings.WebRtcIPHandling,ip_handling_url:settings.WebRtcIPHandlingUrl},
      dns_over_https:{mode:settings.DnsOverHttpsMode},
      net:{network_prediction_options:settings.NetworkPredictionOptions}
    }));
    browser=await chromium.launchPersistentContext(dir,{channel:'chromium',executablePath:process.env.PG_TEST_CHROMIUM,
      env:{...process.env,TZ:process.env.PG_TEST_ZONE},args:[...proxyArgs,'--disable-quic','--disable-background-networking']});
    if (domainMode) {
      // The page also contacts independent IP echo and analytics sites. This fixture tests
      // only its authoritative DNS and WebRTC probes without sending other HTTP requests.
      await browser.route('**/*', route=>{
        const h = new URL(route.request().url()).hostname;
        return h==='ip.net.coffee' || h.endsWith('.ip.net.coffee') ? route.continue() : route.abort();
      });
    }
    const page=await browser.newPage();
    await testUdp(page);
    const result = page.waitForResponse(r=>r.url().startsWith('https://ip.net.coffee/api/dns/result/') && r.ok(), {timeout:60000});
    await page.goto('https://ip.net.coffee/claude/',{waitUntil:'domcontentloaded',timeout:60000});
    for(const key of ['dnsLeakContent','udpLeakContent']){
      const status=page.locator('#'+key+' .tag').first();
      await status.waitFor({timeout:65000});
      console.log(key,(await page.locator('#'+key).innerText()).replace(/\s+/g,' '));
      assert.ok(await status.evaluate(e=>e.classList.contains('tag-safe')),'Net.Coffee reported a warning');
    }
    let reply = await result;
    let addresses = (await reply.json()).dns_servers || [];
    if (!addresses.length) {
      // The first poll can precede delivery to the authoritative server.
      addresses = await page.evaluate(async url => (await (await fetch(url)).json()).dns_servers || [], reply.url());
    }
    assert.ok(addresses.length, 'Net.Coffee did not observe a recursive DNS server');
    for (const ip of new Set(addresses)) {
      assert.ok(require('node:net').isIP(ip));
      const geo = await page.evaluate(async ip => (await fetch('/api/geoip/'+ip)).json(), ip);
      console.log('Observed DNS',ip,geo.country_code,geo.city);
      assert.equal(geo.country_code?.toLowerCase(), country.toLowerCase());
      assert.equal(geo.city?.toLowerCase(), city.toLowerCase());
    }
    const observed=await page.evaluate(()=>Intl.DateTimeFormat().resolvedOptions().timeZone);
    console.log('Browser timezone',observed);
    assert.equal(observed,process.env.PG_TEST_ZONE);
  } finally {
    if (browser) await browser.close();
    fs.rmSync(dir,{recursive:true,force:true});
  }
}
run().catch(e=>{console.error(e.message);process.exitCode=1;});
