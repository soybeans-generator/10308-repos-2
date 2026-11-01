// umber.js marker preserve
'use strict';

// New record shape:
//   A: [ unix timestamp, release year ]
//   B: [ artist, title, url, image? ]
const D = 0; // row.A: timestamp
const Y = 1; // row.A: year

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
   const [,, href, thumb] = row.B;

   let image = thumb;
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
   const [R, T, I] = row.B;

   const artist = I.startsWith('https://youtube.com/') && R.endsWith(' - Topic')
      ? R.slice(0, -' - Topic'.length)
      : R;

   return T.toLowerCase().includes(artist.toLowerCase()) ? T : artist + ' - ' + T;
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
   release.textContent = row.A[Y].toString(10);

   const posted = clone.querySelector('.post');
   posted.textContent = date(row.A[D]);

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

   // `d` is measured from the oldest D in the whole JSON, so fix that
   // first, before any `?t=` filtering changes the list
   const oldest = records.reduce((min, row) => Math.min(min, row.A[D]), Infinity);

   if (query.has('t')) {
      const needle = query.get('t').toLowerCase();
      records = records.filter(row => label(row).toLowerCase().includes(needle));
   }

   // `d` is now the difference between the first D on the page and the
   // oldest D in the JSON, i.e. records[start].D - oldest
   const offset = query.get('d');
   const start = offset === null
      ? 0
      : records.findIndex(row => row.A[D] <= oldest + Number(offset));

   if (start === -1) {
      return;
   }

   const chunk = records.slice(start, start + limit);
   document.getElementById('figures').append(...chunk.map(build));

   // the value for the page whose first row is `records[index]`
   const stamp = index => String(records[index].A[D] - oldest);

   const older = document.getElementById('older');
   if (start + limit < records.length) {
      query.set('d', stamp(start + limit));
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
         query.set('d', stamp(target));
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
// umber.js marker preserve
