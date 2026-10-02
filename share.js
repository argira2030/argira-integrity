// share.js — Registra el service worker y, si la página se abrió desde «Compartir»,
// pone el texto en el cuadro y lo revisa con las reglas LOCALES (rules.js).
// Nada se envía a ningún servidor hasta que la persona pulsa AUDITAR.
(function () {
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});

    const lang = () => ((window.ArgiraI18N && window.ArgiraI18N.currentLang) || document.documentElement.lang || 'es').slice(0, 2);
    const T = {
        es: { title: 'Revisión rápida en tu dispositivo (no se ha enviado nada)',
              green: 'Sin señales conocidas por las reglas locales. Esto no garantiza que sea seguro.',
              yellow: 'Atención: hay señales de posible estafa o presión.',
              red: 'Cuidado: varias señales de estafa. No pagues, no pulses enlaces ni des datos.',
              hint: 'Pulsa AUDITAR para el análisis profundo (envía el texto a los servidores de Argira y puede usar créditos).' },
        en: { title: 'Quick check on your device (nothing was sent)',
              green: 'No signals known to the local rules. This does not guarantee it is safe.',
              yellow: 'Warning: signs of a possible scam or pressure.',
              red: 'Careful: several scam signals. Do not pay, click links or share data.',
              hint: 'Press AUDIT for the deep analysis (sends the text to Argira servers and may use credits).' }
    };

    function show(ta, text) {
        const R = globalThis.ArgiraRules;
        if (!R) return;
        const res = R.evaluate(text, []);
        const t = T[lang()] || T.es;
        const old = document.getElementById('argiraQuick'); if (old) old.remove();
        const box = document.createElement('div');
        box.id = 'argiraQuick';
        box.setAttribute('role', res.level === 'red' ? 'alert' : 'status');
        const col = { green: '#2e7d4f', yellow: '#b8860b', red: '#b3261e' }[res.level];
        box.style.cssText = 'margin:0 0 12px;padding:12px 14px;border-radius:12px;color:#fff;font-size:0.92rem;line-height:1.4;background:' + col;
        const h = document.createElement('strong'); h.textContent = '🛡️ ' + t.title; h.style.display = 'block';
        const p = document.createElement('div'); p.textContent = t[res.level]; p.style.margin = '4px 0';
        box.append(h, p);
        if (res.reasons.length) {
            const ul = document.createElement('ul'); ul.style.cssText = 'margin:4px 0 4px 18px';
            res.reasons.slice(0, 5).forEach(r => { const li = document.createElement('li'); li.textContent = r[lang()] || r.es; ul.appendChild(li); });
            box.appendChild(ul);
        }
        const s = document.createElement('small'); s.textContent = t.hint; s.style.opacity = '0.9';
        box.appendChild(s);
        ta.parentNode.insertBefore(box, ta);
        box.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }

    async function takeShared() {
        if (!/[?&]shared=1/.test(location.search) || !('caches' in window)) return;
        let text = '';
        try {
            const c = await caches.open('argira-share');
            const r = await c.match('shared');
            if (r) { text = await r.text(); await c.delete('shared'); }
        } catch (e) { /* nada */ }
        try { history.replaceState(null, '', location.pathname); } catch (e) { /* nada */ }
        text = text.trim();
        if (!text) return;
        const ta = document.getElementById('inputText');
        if (!ta) return;
        ta.value = text;
        ta.dispatchEvent(new Event('input', { bubbles: true }));
        show(ta, text);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', takeShared);
    else takeShared();
})();
