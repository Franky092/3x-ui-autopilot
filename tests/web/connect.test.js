'use strict';
// Проверки страницы «Подключение» (index.html): логика из <script id="logic"> и политика безопасности.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../../index.html'), 'utf8');
const logic = html.match(/<script id="logic">([\s\S]*?)<\/script>/)[1];
const sandbox = { module: { exports: {} }, URL };
vm.runInNewContext(logic, sandbox);
const L = sandbox.module.exports;

test('subscription links: only complete https links are accepted', () => {
  assert.equal(L.parseSubscription('https://203.0.113.10/abc/def').ok, true);
  assert.equal(L.parseSubscription('  https://203.0.113.10/abc/def  ').host, '203.0.113.10');
  const bad = { '': 'empty', 'https://x.example': 'path', 'https://x.example/': 'path', 'http://x.example/a/b': 'scheme',
    'javascript:alert(1)': 'scheme', 'ftp://x.example/a': 'scheme', 'https://a b.example/x': 'spaces', 'not a link': 'spaces',
    'https://user:pw@x.example/a/b': 'invalid', 'vless://id@host:443': 'scheme', 'abc': 'invalid' };
  for (const [input, reason] of Object.entries(bad)) {
    const r = L.parseSubscription(input);
    assert.equal(r.ok, false, input);
    assert.equal(r.reason, reason, input);
  }
});

test('deep links encode the subscription and the profile name', () => {
  const url = 'https://203.0.113.10/a/b?x=1&y=2';
  const by = Object.fromEntries(L.appCards('windows', url, 'My VPN').map((c) => [c.key, c]));
  assert.equal(by.happ.deep, 'happ://add/' + url);
  assert.equal(by.hiddify.deep, 'hiddify://import/' + url + '#My%20VPN');
  assert.ok(by.clash.deep.startsWith('clash://install-config?url=https%3A%2F%2F203.0.113.10'));
  assert.ok(by.clash.deep.endsWith('&name=My%20VPN'));
  assert.equal(by.v2rayn.deep, null);
  for (const c of Object.values(by)) assert.equal(c.copy, url);
});

test('every platform lists known apps and a download page over https', () => {
  for (const [platform, keys] of Object.entries(L.PLATFORMS)) {
    assert.ok(keys.length >= 3, platform);
    for (const card of L.appCards(platform, 'https://x.example/a/b')) {
      assert.ok(L.APPS[card.key], card.key);
      assert.ok(card.site.startsWith('https://'), card.site);
    }
  }
});

test('platform detection from user agent', () => {
  const cases = { 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)': 'ios', 'Mozilla/5.0 (Linux; Android 14)': 'android',
    'Mozilla/5.0 (Windows NT 10.0; Win64)': 'windows', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)': 'macos',
    'Mozilla/5.0 (X11; Linux x86_64)': 'linux', '': 'windows' };
  for (const [ua, expected] of Object.entries(cases)) assert.equal(L.detectPlatform(ua), expected, ua);
});

test('both languages are complete and have the same keys', () => {
  const keys = (o) => Object.keys(o).sort().join();
  assert.equal(keys(L.TEXT.ru), keys(L.TEXT.en));
  assert.equal(keys(L.TEXT.ru.err), keys(L.TEXT.en.err));
  assert.equal(keys(L.TEXT.ru.platforms), keys(L.TEXT.en.platforms));
  assert.equal(L.TEXT.ru.steps.length, L.TEXT.en.steps.length);
});

test('the page never talks to the network or injects markup', () => {
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/)[1];
  assert.match(csp, /default-src 'none'/);
  assert.ok(!/connect-src/.test(csp) || /connect-src 'none'/.test(csp));
  assert.ok(!/\bscript-src[^;]*https?:/.test(csp));
  assert.ok(!/<script[^>]+src=/i.test(html), 'нет внешних скриптов');
  assert.ok(!/<link[^>]+rel="stylesheet"/i.test(html), 'нет внешних стилей');
  assert.ok(!/fetch\s*\(|XMLHttpRequest|sendBeacon|new WebSocket|innerHTML|insertAdjacentHTML|document\.write|eval\s*\(/.test(html));
});

test('router apps: Nikki and OpenClash need the Clash link, PassWall 2 uses the main link', () => {
  const main = 'https://203.0.113.10/main/id1';
  const clash = 'https://203.0.113.10/clash/id1';
  const withClash = Object.fromEntries(L.appCards('router', main, 'x', clash).map((c) => [c.key, c]));
  assert.deepEqual(Object.keys(withClash).sort(), ['nikki', 'openclash', 'passwall2']);
  assert.equal(withClash.nikki.copy, clash);
  assert.equal(withClash.openclash.copy, clash);
  assert.equal(withClash.passwall2.copy, main);
  for (const c of Object.values(withClash)) assert.equal(c.deep, null);
  const without = Object.fromEntries(L.appCards('router', main, 'x', null).map((c) => [c.key, c]));
  assert.equal(without.nikki.copy, null);      // пока нет Clash-ссылки, копировать нечего
  assert.equal(without.passwall2.copy, main);
});

test('router instructions exist in both languages for every router app', () => {
  for (const lang of ['ru', 'en']) {
    for (const key of L.PLATFORMS.router) {
      assert.ok(L.TEXT[lang].routerSteps[key].length >= 3, lang + ' ' + key);
    }
    assert.ok(L.TEXT[lang].need.clash && L.TEXT[lang].need.auto);
  }
});

test('router install commands: both package managers, official hosts only, no command chaining tricks', () => {
  const hosts = ['github.com', 'sourceforge.net'];
  for (const [key, info] of Object.entries(L.ROUTER_INSTALL)) {
    assert.ok(info.docs.startsWith('https://github.com/'), key);
    assert.ok(info.requires.ru && info.requires.en, key);
    for (const pm of ['opkg', 'apk']) {
      assert.ok(info[pm].length >= 3, key + ' ' + pm);
      for (const line of info[pm]) {
        assert.ok(!/[`$]|\|\|/.test(line), 'подозрительная конструкция: ' + line);
        for (const m of line.matchAll(/https?:\/\/([^/\s]+)/g)) {
          assert.ok(m[0].startsWith('https://'), line);
          assert.ok(hosts.includes(m[1]), 'неожиданный хост ' + m[1] + ' в: ' + line);
        }
      }
    }
    assert.ok(info.opkg.some((l) => /opkg/.test(l)) && info.apk.some((l) => /apk/.test(l)), key);
  }
});

test('Nikki quick install uses the official feed script then installs both packages', () => {
  const n = L.ROUTER_INSTALL.nikki;
  assert.match(n.opkg[0], /OpenWrt-nikki\/raw\/refs\/heads\/main\/feed\.sh \| ash$/);
  assert.ok(n.opkg.some((l) => /opkg install nikki luci-app-nikki/.test(l)));
  assert.ok(n.apk.some((l) => /apk add nikki luci-app-nikki/.test(l)));
});

test('page points to the automatic router install command for every router app', () => {
  assert.match(html, /"autopilot router " \+ card\.key/);
  for (const lang of ['ru', 'en']) assert.ok(L.TEXT[lang].auto.length > 20);
});

test('XKeen is not offered', () => {
  assert.ok(!/xkeen/i.test(html));
});
