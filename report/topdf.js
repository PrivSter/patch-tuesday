// Render the report page to an A4 landscape PDF with the preinstalled Chromium.
// node report/topdf.js <page.html> <out.pdf> "<footer text>"
// Needs playwright@1.47.2 (npm install it if require fails). Don't run `playwright install`.
// Google Fonts can't be downloaded here, so local fonts (Inter, DejaVu Sans Mono) are swapped in.
const { chromium } = require('playwright'); const fs = require('fs'); const path = require('path');
const [src, out, foot] = process.argv.slice(2);
(async () => {
  // The page is a fragment (the Artifact publisher adds the skeleton), so wrap it the same way here.
  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<style>body{margin:0}[hidden]{display:none!important}img{max-width:100%}</style></head><body>' + fs.readFileSync(src, 'utf8')
    + '<style>:root{--display:"Inter Display","Inter",sans-serif!important;--body:"Inter",sans-serif!important;--mono:"DejaVu Sans Mono",monospace!important}</style></body></html>';
  const tmp = out.replace(/\.pdf$/, '.print.html'); fs.writeFileSync(tmp, html);
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
  const pg = await b.newPage(); await pg.emulateMedia({ media: 'print', colorScheme: 'light' });
  await pg.goto('file://' + path.resolve(tmp), { waitUntil: 'load', timeout: 30000 });
  await pg.pdf({ path: out, preferCSSPageSize: true, printBackground: true, displayHeaderFooter: true, headerTemplate: '<span></span>',
    footerTemplate: '<div style="font-size:7pt;width:100%;padding:0 12mm;color:#555;display:flex;justify-content:space-between;font-family:sans-serif"><span>'
      + (foot || '').replace(/</g, '&lt;') + '</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>' });
  await b.close();
})();
