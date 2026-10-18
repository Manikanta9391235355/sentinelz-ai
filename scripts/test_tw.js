const fs = require('fs');
const postcss = require('postcss');
const tailwind = require('@tailwindcss/postcss');

const css = fs.readFileSync('src/app/globals.css', 'utf8');
postcss([tailwind()]).process(css, { from: 'src/app/globals.css' })
  .then(result => {
    console.log('Result CSS length:', result.css.length);
    console.log('Contains .flex:', result.css.includes('.flex'));
    console.log('Contains bg-slate-900:', result.css.includes('bg-slate-900'));
    console.log('Contains text-blue-500:', result.css.includes('text-blue-500'));
  })
  .catch(err => {
    console.error('PostCSS error:', err);
  });
