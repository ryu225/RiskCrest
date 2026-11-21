(()=>{
'use strict';
for (const toggle of document.querySelectorAll('.password-toggle')) {
  toggle.addEventListener('click', () => {
    const input = document.getElementById(toggle.dataset.target);
    if (!input) return;
    const hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    toggle.textContent = hidden ? 'Hide' : 'Show';
    toggle.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
  });
}


// Revalidate protected pages when browser history restores an earlier DOM.
// HTTP no-store protects ordinary caching, but bfcache may restore a snapshot
// without asking the server. Hiding it on pagehide prevents a stale flash.
if (document.body.dataset.securePrivatePage === 'true') {
  window.addEventListener('pagehide', () => {
    document.documentElement.style.visibility = 'hidden';
  });
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      // Fetch the page again; the server will redirect to sign-in if logged out.
      window.location.reload();
    }
  });
}

// Homepage access-policy illustration. Visual only; real authorization stays server-side.
const riskcrestRoleButtons = document.querySelectorAll('#policy-demo [data-role]');
const riskcrestAdminStatus = document.querySelector('#policy-demo [data-policy="admin"]');
const riskcrestAdminReason = document.querySelector('#policy-demo [data-reason="admin"]');
if (riskcrestAdminStatus && riskcrestAdminReason) {
  riskcrestRoleButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const admin = button.dataset.role === 'admin';
      riskcrestRoleButtons.forEach((item) => {
        const selected = button === item;
        item.classList.toggle('selected', selected);
        item.setAttribute('aria-pressed', String(selected));
      });
      riskcrestAdminStatus.classList.toggle('is-allowed', admin);
      riskcrestAdminStatus.classList.toggle('is-denied', !admin);
      riskcrestAdminStatus.textContent = admin ? 'Allowed' : 'Denied';
      riskcrestAdminReason.textContent = admin ? 'Accessible to administrators' : 'Reserved for administrators';
    });
  });
}

})();
