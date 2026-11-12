// Run: node tests/import.test.js   (checks the list parsers and the merge rules from index.html)
const fs = require('fs'), assert = require('assert');
const html = fs.readFileSync(__dirname + '/../index.html', 'utf8');
const a = html.indexOf('// ---- Import:'), b = html.indexOf('const doImport');
assert(a > 0 && b > a, 'import section not found');
const make = data => new Function('data', 'nid', 't', 'lang', html.slice(a, b) + ';return{parseList,mergeImport,backupTxt}')(data, () => data.reduce((m, x) => Math.max(m, +x.id || 0), 0) + 1, k => k, 'ru');

let data = [{ id: 1, site: 'Google', login: 'a@b.c', password: 'x1' }];
let { parseList, mergeImport, backupTxt } = make(data);

// Chrome-style CSV: quotes, commas inside a field, site from a url
const csv = 'name,url,username,password,note\ngithub.com,https://github.com/login,me@x.com,"p,w""1",work\n,https://www.steamcommunity.com/,gamer,pass2,\nGoogle,https://accounts.google.com,a@b.c,x1,';
const rows = parseList(csv);
assert.strictEqual(rows.length, 3);
assert.strictEqual(rows[0].password, 'p,w"1');
assert.strictEqual(rows[0].site, 'Github');
assert.deepStrictEqual(mergeImport(rows), [2, 1]); // the Google row is a duplicate

// our own text backup
const txt = 'Мои пароли — 12.11.2026\r\n\r\nDISCORD\r\n1. u1\r\n   Пароль: pw1\r\n   Заметка: main\r\n2. —\r\n   Пароль: pw2\r\n';
const t = parseList(txt);
assert.deepStrictEqual(t.map(x => [x.site, x.login, x.password, x.note]), [['Discord', 'u1', 'pw1', 'main'], ['Discord', '', 'pw2', '']]);

// our own json backup: sections, icons (only safe ones), odd site names
const js = JSON.stringify([
  { site: 'Roblox', login: 'r1', password: 'rp', note: '', icon: 'brand:Roblox' },
  { site: 'Empty', section: true, icon: 'javascript:alert(1)' },
  { site: 'constructor', login: 'c', password: 'c' },
]);
data.length = 0; ({ parseList, mergeImport, backupTxt } = make(data));
assert.deepStrictEqual(mergeImport(parseList(js)), [2, 0]);
assert.strictEqual(data.find(x => x.site === 'Roblox').icon, 'brand:Roblox');
assert.strictEqual(data.find(x => x.site === 'Empty').icon, undefined); // unsafe icon dropped
assert.strictEqual(data.find(x => x.site === 'constructor').login, 'c');
assert.strictEqual(new Set(data.map(x => x.id)).size, data.length); // ids are unique

// plain "login:password" lines
assert.deepStrictEqual(parseList('mail:pass1\nother:pass2').map(x => x.login), ['mail', 'other']);
// the text backup contains every entry and can be read back by the importer
const all = [{ id: 1, site: 'Zeta', login: 'z', password: 'pz' }, { id: 2, site: 'Alpha', login: '', password: 'pa', note: 'n1' }, { id: 3, site: 'Empty', section: true }];
const back = parseList(backupTxt(all));
assert.deepStrictEqual(back.map(x => [x.site, x.login, x.password, x.note]), [['Alpha', '', 'pa', 'n1'], ['Zeta', 'z', 'pz', '']]);
// the page's weak-password rule gives the same answers as the Rust one (same lists as main.rs tests)
{
  const a = html.indexOf('const weakPw='), b = html.indexOf('async function unlock');
  assert(a > 0 && b > a, 'weakPw not found');
  const weakPw = new Function(html.slice(a, b) + ';return weakPw')();
  for (const w of ['aaaaaaaaaaaa', '123456789012', 'abcdefghijkl', 'zyxwvutsrqpo', 'Qwerty-12345x', 'MyPassword9876', '121212121212']) assert(weakPw(w), w);
  for (const w of ['pNUblQtKozml', 'k3Rt9vXq2LmZ', 'чайник-гитара-42']) assert(!weakPw(w), w);
}
console.log('import tests passed');
