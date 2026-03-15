const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const raw = fs.readFileSync('_worker.js', 'utf8').replace(/export default\s*\{/, 'const __default__ = {');
const wrapped = `(function(){ ${raw}; return { buildFilterConfig, buildPlainNodeResult, filterAndSortPlainNodes, filterClashProxies, scoreNodeLine, buildSubConverterUrl }; })()`;
const context = {
  console,
  TextEncoder,
  TextDecoder,
  atob: (s) => Buffer.from(s, 'base64').toString('binary'),
  btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
  crypto: { subtle: { digest: async () => new Uint8Array(16).buffer } },
  Response: class {},
  Request: class {},
  Headers: class { constructor(){} set(){} },
  URL,
  URLSearchParams,
  fetch: async () => { throw new Error('fetch not allowed in tests'); },
};
vm.createContext(context);
const { buildFilterConfig, buildPlainNodeResult, filterAndSortPlainNodes, filterClashProxies, scoreNodeLine, buildSubConverterUrl } = vm.runInContext(wrapped, context);

function test(name, fn) {
  try { fn(); console.log('PASS', name); }
  catch (e) { console.error('FAIL', name); console.error(e); process.exitCode = 1; }
}

test('default config is conservative', () => {
  const cfg = buildFilterConfig(new URL('https://a.com/auto'), {});
  assert.equal(cfg.enabled, true);
  assert.equal(cfg.drop80ws, false);
  assert.equal(cfg.maxSameHost, 0);
  assert.equal(cfg.dedupeMode, 'ip');
  assert.equal(cfg.maxSameIp, 1);
  assert.equal(cfg.mode, 'conservative');
});

test('query can disable filter', () => {
  const cfg = buildFilterConfig(new URL('https://a.com/auto?filter=off'), {});
  assert.equal(cfg.enabled, false);
});

test('filter off preserves duplicate lines in final output', () => {
  const cfg = buildFilterConfig(new URL('https://a.com/auto?filter=off'), {});
  const text = [
    'vless://u@a:443?security=tls&type=ws#A',
    'vless://u@a:443?security=tls&type=ws#A',
  ].join('\n');
  const out = buildPlainNodeResult(text, cfg);
  assert.equal(out.split('\n').length, 2);
});

test('drop 80 ws and prefer 443 tls', () => {
  const lines = [
    'vless://u@104.17.1.1:80?type=ws&host=crayfornick-ew.pages.dev#80WS',
    'vless://u@104.17.1.1:443?security=tls&type=ws&host=crayfornick-ew.pages.dev#443TLS',
    'trojan://p@domain.com:443?security=tls&type=ws#TRJ',
  ];
  const out = filterAndSortPlainNodes(lines, { enabled:true, drop80ws:true, maxSameHost:3, excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.equal(out.length, 2);
  assert.ok(out[0].includes(':443'));
  assert.ok(!out.some(x => x.includes(':80?type=ws')));
});

test('limit same host duplicates', () => {
  const lines = [1,2,3,4].map(i => `vless://u@104.17.${i}.1:443?security=tls&type=ws&host=crayfornick-ew.pages.dev#N${i}`);
  const out = filterAndSortPlainNodes(lines, { enabled:true, drop80ws:false, maxSameHost:2, dedupeMode:'host', excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.equal(out.length, 2);
});

test('include/exclude keywords work', () => {
  const lines = [
    'vless://u@a.com:443?security=tls&type=ws#原生地址',
    'vless://u@b.com:443?security=tls&type=ws#HKG',
    'vless://u@c.com:443?security=tls&type=ws#SJC',
  ];
  const out = filterAndSortPlainNodes(lines, { enabled:true, drop80ws:false, maxSameHost:3, excludeKeywords:['sjc'], includeKeywords:['原生','hkg'], mode:'conservative' });
  assert.equal(out.length, 2);
  assert.ok(out.every(x => !x.toLowerCase().includes('sjc')));
});

test('score prefers tls443 over 80ws', () => {
  assert.ok(scoreNodeLine('vless://u@a:443?security=tls&type=ws#A') > scoreNodeLine('vless://u@a:80?type=ws#B'));
});

test('subconverter url omits config when empty', () => {
  const url = buildSubConverterUrl('https', 'sub.example.com', 'clash', 'https://src.example.com/sub', '');
  assert.ok(!url.includes('config='));
});

test('subconverter url includes config when provided', () => {
  const url = buildSubConverterUrl('https', 'sub.example.com', 'clash', 'https://src.example.com/sub', 'https://cfg.example.com/rules.ini');
  assert.ok(url.includes('config='));
});

test('clash proxy filter removes 80 ws and limits same servername', () => {
  const yaml = `proxies:\n  - {name: A1, server: 104.17.1.1, port: 80, type: vless, network: ws, ws-opts: {headers: {Host: crayfornick-ew.pages.dev}}}\n  - {name: A2, server: 104.17.1.2, port: 443, type: vless, tls: true, network: ws, servername: crayfornick-ew.pages.dev, ws-opts: {headers: {Host: crayfornick-ew.pages.dev}}}\n  - {name: A3, server: 104.17.1.3, port: 443, type: vless, tls: true, network: ws, servername: crayfornick-ew.pages.dev, ws-opts: {headers: {Host: crayfornick-ew.pages.dev}}}\n  - {name: A4, server: 104.17.1.4, port: 443, type: vless, tls: true, network: ws, servername: crayfornick-ew.pages.dev, ws-opts: {headers: {Host: crayfornick-ew.pages.dev}}}`;
  const out = filterClashProxies(yaml, { enabled:true, drop80ws:true, maxSameHost:2, dedupeMode:'host', excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.ok(!out.includes('port: 80'));
  const proxies = out.split('\n').filter(x => x.includes('{name:'));
  assert.ok(proxies.length <= 2);
});

test('clash proxy filter handles multi-line proxy blocks', () => {
  const yaml = `proxies:\n  - name: A1\n    server: 104.17.1.1\n    port: 80\n    type: vless\n    network: ws\n    ws-opts:\n      headers:\n        Host: example.com\n  - name: A2\n    server: 104.17.1.2\n    port: 443\n    type: vless\n    tls: true\n    network: ws\n    servername: example.com\n    ws-opts:\n      headers:\n        Host: example.com\nproxy-groups:\n  - name: auto`;
  const out = filterClashProxies(yaml, { enabled:true, drop80ws:true, maxSameHost:1, excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.ok(!out.includes('port: 80'));
  assert.equal((out.match(/^\s*-\s+name:/mg) || []).length, 2);
  assert.ok(out.includes('proxy-groups:'));
});

test('clash proxy filter prunes missing proxy references from groups', () => {
  const yaml = `proxies:\n  - {name: A1, server: 104.17.1.1, port: 80, type: vless, network: ws, ws-opts: {headers: {Host: example.com}}}\n  - {name: A2, server: 104.17.1.2, port: 443, type: vless, tls: true, network: ws, servername: example.com, ws-opts: {headers: {Host: example.com}}}\nproxy-groups:\n  - {name: auto, type: select, proxies: [A1, A2, DIRECT]}`;
  const out = filterClashProxies(yaml, { enabled:true, drop80ws:true, maxSameHost:1, excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.ok(!out.includes('A1, A2'));
  assert.ok(out.includes('proxies: [A2, DIRECT]'));
});

test('clash proxy filter keeps group-to-group refs and prunes broken rules refs', () => {
  const yaml = `proxies:\n  - {name: A1, server: 104.17.1.1, port: 80, type: vless, network: ws, ws-opts: {headers: {Host: example.com}}}\n  - {name: A2, server: 104.17.1.2, port: 443, type: vless, tls: true, network: ws, servername: example.com, ws-opts: {headers: {Host: example.com}}}\nproxy-groups:\n  - {name: ♻️ 自动选择, type: select, proxies: [A1, A2]}\n  - {name: 🎯 全球直连, type: select, proxies: [DIRECT]}\n  - {name: 🔰 节点选择, type: select, proxies: [♻️ 自动选择, 🎯 全球直连]}\nrules:\n  - DOMAIN-SUFFIX,local,🎯 全球直连\n  - DOMAIN-SUFFIX,foo.example,不存在组`;
  const out = filterClashProxies(yaml, { enabled:true, drop80ws:true, maxSameHost:1, excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.ok(out.includes('proxies: [A2]'));
  assert.ok(out.includes('proxies: [♻️ 自动选择, 🎯 全球直连]'));
  assert.ok(out.includes('DOMAIN-SUFFIX,local,🎯 全球直连'));
  assert.ok(!out.includes('DOMAIN-SUFFIX,foo.example,不存在组'));
});

test('clash proxy filter prunes MATCH rule when target group missing', () => {
  const yaml = `proxies:\n  - {name: A1, server: 104.17.1.2, port: 443, type: vless, tls: true, network: ws, servername: example.com, ws-opts: {headers: {Host: example.com}}}\nproxy-groups:\n  - {name: 🎯 全球直连, type: select, proxies: [DIRECT]}\nrules:\n  - MATCH,🐟 漏网之鱼\n  - MATCH,🎯 全球直连`;
  const out = filterClashProxies(yaml, { enabled:true, drop80ws:true, maxSameHost:1, excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.ok(!out.includes('MATCH,🐟 漏网之鱼'));
  assert.ok(out.includes('MATCH,🎯 全球直连'));
});

test('clash proxy filter keeps non-removed group members', () => {
  const yaml = `proxies:\n  - {name: A1, server: 1.1.1.1, port: 80, type: vless, network: ws}\n  - {name: A2, server: 1.1.1.2, port: 443, type: vless, tls: true, network: ws}\n  - {name: A3, server: 1.1.1.3, port: 443, type: vless, tls: true, network: ws}\nproxy-groups:\n  - {name: G1, type: select, proxies: [A1, A2, A3, DIRECT]}\n  - {name: G2, type: select, proxies: [G1, A2]}\nrules:\n  - MATCH,G2`;
  const out = filterClashProxies(yaml, { enabled:true, drop80ws:true, maxSameHost:10, excludeKeywords:[], includeKeywords:[], mode:'conservative' });
  assert.ok(out.includes('proxies: [A2, A3, DIRECT]'));
  assert.ok(out.includes('proxies: [G1, A2]'));
});
