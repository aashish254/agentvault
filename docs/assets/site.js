/* Copy-to-clipboard for the install command. No framework, no analytics. */
(function () {
  'use strict';

  var live = document.createElement('p');
  live.setAttribute('aria-live', 'polite');
  live.setAttribute('role', 'status');
  live.style.cssText = 'position:absolute;left:-9999px';
  document.body.appendChild(live);

  function flash(btn, msg) {
    var prev = btn.textContent;
    btn.textContent = msg;
    live.textContent = msg === 'copy' ? '' : 'Install command copied to clipboard';
    window.setTimeout(function () { btn.textContent = prev; }, 1800);
  }

  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = document.getElementById(btn.getAttribute('data-copy')).textContent.trim();
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(
          function () { flash(btn, 'copied'); },
          function () { flash(btn, 'press ⌘C'); }
        );
        return;
      }
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:absolute;left:-9999px';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      flash(btn, ok ? 'copied' : 'press ⌘C');
    });
  });

  /* Wide tables scroll sideways on narrow screens; fade the edge only while
     there is more to see. */
  document.querySelectorAll('.table-scroll').forEach(function (box) {
    function update() {
      var room = box.scrollWidth - box.clientWidth - box.scrollLeft;
      box.classList.toggle('scrolls', box.scrollWidth > box.clientWidth + 2 && room > 2);
    }
    box.addEventListener('scroll', update, { passive: true });
    window.addEventListener('resize', update);
    update();
  });
})();
