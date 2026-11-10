'use strict';

// New record shape:
//   A: [ unix timestamp, release year ]
//   B: [ artist, title, url, image? ]
const STAMP = 0;  // row.A: unix timestamp
const YEAR = 1;   // row.A: year
const ARTIST = 0; // row.B: artist
const TITLE = 1;  // row.B: title
const HREF = 2;   // row.B: url
const THUMB = 3;  // row.B: image

const formatter = new Intl.DateTimeFormat('en', {
   weekday: 'short',
   month: 'short',
   day: 'numeric',
   year: 'numeric'
});

function date(timestamp) {
   const time = new Date(timestamp * 1000);

   return formatter.formatToParts(time)
      .filter(part => part.type !== 'literal')
      .map(part => part.value)
      .join(' ');
}

function media(row) {
   const href = row.B[HREF];

   let image = row.B[THUMB];
   if (image === undefined) {
      // B[3] is omitted only for YouTube rows on the default thumbnail
      const video = new URL(href).searchParams.get('v');
      image = 'https://i.ytimg.com/vi_webp/' + video + '/sddefault.webp';
   }

   return {
      href: href,
      src: image
   };
}

const template = document.querySelector('template');
const limit = 10;

function label(row) {
   const artist = row.B[ARTIST];
   const title = row.B[TITLE];
   const href = row.B[HREF];

   const name = href.startsWith('https://youtube.com/') && artist.endsWith(' - Topic')
      ? artist.slice(0, -' - Topic'.length)
      : artist;

   return title.toLowerCase().includes(name.toLowerCase()) ? title : name + ' - ' + title;
}

function build(row) {
   const clone = template.content.cloneNode(true);
   const { href, src } = media(row);

   const link = clone.querySelector('a');
   link.target = '_blank';
   link.href = href;

   const image = clone.querySelector('img');
   image.src = src;

   const title = clone.querySelector('thead td');
   title.textContent = label(row);

   const release = clone.querySelector('.release');
   release.textContent = row.A[YEAR].toString(10);

   const posted = clone.querySelector('.post');
   posted.textContent = date(row.A[STAMP]);

   const td_view = clone.querySelector('td.view');
   const th_view = clone.querySelector('th.view');
   const view = localStorage.getItem(link.href);
   if (view !== null) {
      td_view.textContent = view;
   } else {
      th_view.style.display = 'none';
   }

   const views = () => {
      const count = Number(localStorage.getItem(link.href)) + 1;
      localStorage.setItem(link.href, count);
      th_view.style.display = td_view.style.display = '';
      td_view.textContent = count;
   };
   link.addEventListener('click', views);

   return clone;
}

async function main() {
   const response = await fetch('/umber/umber.json');
   let records = await response.json();

   // `d` is measured from the oldest STAMP in the whole JSON, so fix that
   // first, before any `?t=` filtering changes the list
   const oldest = records.reduce((min, row) => Math.min(min, row.A[STAMP]), Infinity);

   if (query.has('t')) {
      const needle = query.get('t').toLowerCase();
      records = records.filter(row => label(row).toLowerCase().includes(needle));
   }

   // `d` is now the difference between the first STAMP on the page and the
   // oldest STAMP in the JSON, i.e. records[start].A[STAMP] - oldest
   const offset = query.get('d');
   const start = offset === null
      ? 0
      : records.findIndex(row => row.A[STAMP] <= oldest + Number(offset));

   if (start === -1) {
      return;
   }

   const chunk = records.slice(start, start + limit);
   document.getElementById('figures').append(...chunk.map(build));

   // the value for the page whose first row is `records[index]`
   const offsetOf = index => String(records[index].A[STAMP] - oldest);

   const older = document.getElementById('older');
   if (start + limit < records.length) {
      query.set('d', offsetOf(start + limit));
      older.href = '?' + query.toString();
   } else {
      older.remove();
   }

   const newer = document.getElementById('newer');
   if (start > 0) {
      const target = Math.max(0, start - limit);
      if (target === 0) {
         query.delete('d'); // the natural default: start at the newest page
      } else {
         query.set('d', offsetOf(target));
      }
      newer.href = '?' + query.toString();
   } else {
      newer.remove();
   }
}

document.querySelector('form').onsubmit = function() {
   document.querySelector('input').blur();
   this.submit();
   this.reset();
   return false;
};

const query = new URLSearchParams(location.search);
main();
