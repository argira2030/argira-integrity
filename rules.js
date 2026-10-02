// rules.js — Detector LOCAL de señales de estafa (no usa red, no gasta créditos).
// Se carga como content script antes de content.js. Los pesos y umbrales son
// provisionales: ajústalos con casos reales (ver LEVELS al final).
(function (root) {
    const norm = (s) => String(s || '').toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '');

    // Los patrones se escriben SIN tildes porque el texto se normaliza antes.
    const TEXT_RULES = [
        { id: 'advance_fee', w: 3,
          es: 'Pide dinero o un pago por adelantado', en: 'Asks for money or an upfront payment',
          re: /pago (por )?adelantado|pagar (una |un )?(pequena |pequeno )?(tasa|cuota|fianza|deposito)|tasa de (inscripcion|registro|activacion|desbloqueo)|transferencia previa|(solo )?(tienes|debes|tendras|hay) que pagar (el |los )?(envio|gastos de envio)|paga(r)? (solo )?(el )?(coste|gastos) del? envio|deposito (inicial )?(requerido|obligatorio)|upfront (fee|payment)|pay (a|an|the) (small )?(fee|deposit) (to|before|first)|western union|moneygram|compra(r|s)? (unas? )?(tarjetas? (de )?regalo|gift ?cards?)|buy (some |the )?gift ?cards?|we will reimburse you|te reembolsamos/ },
        // Mención suelta (tiendas, aerolíneas…): pesa poco; el pago fuerte de arriba prevalece.
        { id: 'fee_mention', w: 1, skipIf: 'advance_fee',
          es: 'Menciona tasas o tarjetas regalo', en: 'Mentions fees or gift cards',
          re: /gift ?cards?|tarjetas? (de )?regalo|registration fee|processing fee/ },
        { id: 'task_scam', w: 3,
          es: 'Típico fraude de "tareas sencillas a cambio de comisión"', en: 'Typical "simple tasks for commission" job scam',
          re: /(tareas|pedidos) (sencillas|simples|faciles)|simple (online )?tasks?|comision por (cada )?(tarea|pedido)|optimizacion de (pedidos|productos)|boost (orders|products)|dar (me gusta|likes?) .{0,30}gana|(like|liking) (videos|posts) .{0,30}earn/ },
        { id: 'crypto_invest', w: 4,
          es: 'Promete inversión o rentabilidad garantizada', en: 'Promises guaranteed investment returns',
          re: /duplica(r)? (tu|su) (inversion|dinero|capital)|double your (investment|money|crypto)|(rentabilidad|retorno|beneficios?|ganancias?) garantizad[oa]s?|guaranteed (returns?|profits?|income)|100% (seguro|garantizado|safe|guaranteed)|(inversion|inversiones|ganancias|trading|beneficios) sin riesgo|risk[- ]free (investment|profit|trading)|opciones binarias|binary options|senales de (trading|forex)|(forex|crypto|trading) signals|minado en la nube|cloud mining|garantizamos .{0,40}(capital|inversion|dinero|beneficios|ganancias)|(triplica|multiplica|duplica)(r|s)? (tu|su) (capital|inversion|dinero)|(triplicar|multiplicar|duplicar)as (tu|su) (capital|inversion|dinero)/ },
        { id: 'phishing_account', w: 3,
          es: 'Intenta que verifiques tu cuenta o des tus claves', en: 'Tries to get you to verify your account or share credentials',
          re: /(verifica|verifique|valida|valide|confirma|confirme|reactiva|reactive) (hoy |ahora |inmediatamente )?(tu|su|tus|sus|los datos de tu|los datos de su) (cuenta|contrasena|identidad|tarjeta|datos|informacion)|(actualiza|actualice) (tu|su|tus|sus) (cuenta|contrasena|tarjeta|datos (bancarios|de pago|de tarjeta)|informacion de pago|metodo de pago)|(tu|su) cuenta (sera|ha sido|esta|va a ser|quedara|fue|podria ser) (suspendida|bloqueada|limitada|restringida|comprometida|cancelada|desactivada)|(acceso|actividad|inicio de sesion|intento de acceso) (inusual|sospechos[oa])|hemos detectado (un|una) .{0,30}(sospechos|inusual)|(introduce|introduzca|ingresa|ingrese|facilita|facilite|indica|indique|envia|envie)(nos)? (tus|sus) datos (de )?(tarjeta|pago|bancarios)|(verify|confirm|update|validate|reactivate) your (account|password|identity|card|payment|billing)|your account (will be|has been|is) (suspended|locked|limited|restricted|compromised|disabled)|unusual (sign[- ]?in|activity) (detected|on your)|(introduce|ingresa|envia|comparte)(nos)? tu (contrasena|clave|pin|codigo (de )?(verificacion|sms|seguridad))|(enter|send|share|provide) your (password|pin|otp|verification code|security code)/ },
        { id: 'payment_failed', w: 2,
          es: 'Dice que tu pago falló y que perderás el servicio', en: 'Says your payment failed and you will lose the service',
          re: /(su|tu) (pago|cobro|tarjeta) (ha sido|fue|esta) (rechazad[oa]|denegad[oa]|declinad[oa])|(perdera|perderas|perdera usted) (el |tu |su )?(servicio|acceso|cuenta)|your payment (was|has been) (declined|rejected)/ },
        { id: 'deadline_threat', w: 2,
          es: 'Plazo corto unido a una amenaza (bloqueo, pérdida, cancelación)', en: 'Short deadline combined with a threat (block, loss, cancellation)',
          re: /(en|dentro de) (las proximas )?\d+ (horas|minutos).{0,60}(bloque|suspend|cancel|perder|cierre|eliminac)|(bloque|suspend|cancel|elimin)\w*.{0,60}(en|dentro de) (las proximas )?\d+ (horas|minutos)|(hoy mismo|inmediatamente|ahora mismo|de inmediato|antes de manana).{0,60}(bloque|suspend|cancel|perdera|multa|corte)|(bloque|suspend|cancel)\w*.{0,80}(hoy mismo|inmediatamente)|within \d+ (hours|minutes).{0,60}(suspend|lock|close|cancel)/ },
        { id: 'parcel_fee', w: 3,
          es: 'Paquete retenido y tasas que hay que pagar', en: 'Held parcel and fees you must pay',
          re: /(paquete|envio|pedido) (esta |ha sido |fue )?(retenid[oa]|detenid[oa]|bloquead[oa]) (en|por)|retenid[oa] en (la )?aduana|paga(r)? [\d.,]+\s?(€|eur|euros) (de )?(tasas|gastos|aduana|envio)|(tasas|gastos) de (aduana|liberacion|reexpedicion)|(your|the) (parcel|package) (is|has been) (held|on hold).{0,60}(fee|pay)/ },
        { id: 'tax_refund', w: 3,
          es: 'Devolución o multa «oficial» inesperada', en: 'Unexpected «official» refund or fine',
          re: /(hacienda|agencia tributaria|aeat|dgt|seguridad social).{0,60}(devolucion|reembolso|multa|deuda|sancion)|devolucion (pendiente )?de [\d.,]+\s?(€|eur|euros)|reembolso pendiente|(tax refund|irs).{0,40}(refund|owe)/ },
        { id: 'family_scam', w: 3,
          es: 'Típico mensaje de «soy tu hijo/a, número nuevo, necesito dinero»', en: 'Typical «it\'s your child, new number, I need money» message',
          re: /(se me ha (roto|estropeado|caido)|he perdido|me han robado) (el |mi )?(movil|telefono)|(hazme|me hagas|me haces|me puedes hacer|necesito) (un |una )?(bizum|transferencia) (urgente)?|(bizum|transferencia) urgente|hi mom.{0,40}new number/ },
        // «Número nuevo» solo: mensaje normal entre conocidos; suma poco y avisa junto a una petición de dinero.
        { id: 'new_number', w: 2,
          es: 'Dice que es un número nuevo', en: 'Says it is a new number',
          re: /(este es |es |desde )?mi (numero|telefono|movil) nuevo|this is my new number/ },
        { id: 'boss_scam', w: 3,
          es: 'Falso jefe o director que pide una transferencia', en: 'Fake boss asking for a transfer',
          re: /soy (el|tu) (director|jefe|ceo|gerente|presidente|administrador).{0,100}(transferencia|pago|bizum|tarjetas)|necesito que (hagas|realices|me hagas) (una |un )?(transferencia|pago|bizum)|(transferencia|pago|bizum) (urgente|hoy mismo|inmediata)/ },
        { id: 'secrecy', w: 2,
          es: 'Te pide que no se lo cuentes a nadie', en: 'Asks you not to tell anyone',
          re: /no se lo (cuentes|digas|comentes) a nadie|no (cuentes|digas|hables|comentes) (esto |de esto )?(a|con) nadie|no lo (cuentes|comentes|hables)( con nadie| a nadie)|keep this (a secret|secret|between us)|don't tell anyone/ },
        { id: 'secret_offer', w: 2,
          es: 'Oferta «secreta» o «exclusiva»', en: '«Secret» or «exclusive» offer',
          re: /oportunidad (secreta|exclusiva|unica)|solo (unos pocos|unas pocas|conocemos|lo sabemos)|informacion (privilegiada|confidencial) (para|sobre) invertir|secret (opportunity|method)/ },
        { id: 'subscription_scam', w: 3,
          es: 'Cobro de suscripción que no reconoces y un teléfono al que llamar', en: 'Charge for a subscription you don\'t recognise and a number to call',
          re: /(suscripcion|membresia|cargo|pago) .{0,40}(renovara|renovada|renovado|se cobrara|se cargara|cargaremos).{0,40}[\d.,]+\s?(€|eur|euros|\$|usd)|si no (la |lo |el )?reconoces.{0,40}llama|llama (inmediatamente|ahora|urgentemente|ya) (a este|al)|call (this number|us) (immediately|now)/ },
        { id: 'chain_hoax', w: 3,
          es: 'Cadena: «compártelo antes de que lo borren»', en: 'Chain message: «share it before they delete it»',
          re: /comparte (esto|este mensaje|este video) con \d+|reenvia(lo)? a \d+|antes de que (lo )?(borren|eliminen|censuren|bloqueen)|(los )?medios no (quieren|te lo)|no quieren que (lo )?sepas|difunde (esto|este mensaje)|share this with \d+/ },
        { id: 'quick_return', w: 2,
          es: 'Promete multiplicar una cantidad en pocos días', en: 'Promises to multiply a sum in a few days',
          re: /inviert[ea] [\d.,]+\s?(€|eur|euros)?.{0,30}(recibe|recibiras|gana|ganaras|obten)|recibe [\d.,]+\s?(€|eur|euros) en \d+ (horas|dias)|invest [\d.,$]+.{0,30}(get|receive|earn) [\d.,$]+/ },
        { id: 'personal_data', w: 2,
          es: 'Pide documentos o datos bancarios', en: 'Asks for ID documents or bank details',
          re: /(envia(nos)?|manda(nos)?|adjunta|facilita(nos)?|proporciona(nos)?) (tu|una copia de tu|foto de tu) (dni|nie|pasaporte|documento de identidad|numero de cuenta|iban|datos bancarios|tarjeta)|(send|provide|share|upload) (us )?(a )?(copy of )?your (passport|id card|driver'?s licen[cs]e|ssn|social security|bank (account|details)|iban|credit card)|numero de la seguridad social/ },
        { id: 'prize', w: 3,
          es: 'Anuncia premios, herencias o fondos inesperados', en: 'Announces unexpected prizes, inheritances or funds',
          re: /has ganado|enhorabuena.{0,40}(ganado|premio|ganador)|ha sido (seleccionad[oa]|elegid[oa]) (como )?ganador|felicidades.{0,40}(ganador|premio)|you('ve| have) won|congratulations.{0,40}(won|winner|prize|selected)|loteria|lottery|herencia (de|millonaria)|inheritance|unclaimed (funds|prize)|fondos (sin reclamar|congelados)/ },
        { id: 'fake_income', w: 2,
          es: 'Ingresos fáciles o irreales', en: 'Easy or unrealistic income',
          re: /gana(r|s)? (hasta )?\d[\d.,]*\s?(€|eur|euros|\$|usd|dolares)\s?(al dia|diarios|por dia|a la semana|semanales|por hora|al mes)|earn (up to )?\$?\d[\d,.]*\s?(usd|\$|dollars)?\s?(per|a|\/)\s?(day|hour|week)|ingresos? pasivos?|passive income|libertad financiera|financial freedom|dinero facil|easy money|get rich|trabaja desde casa (y )?gana|work from home (and )?earn/ },
        { id: 'offplatform', w: 2,
          es: 'Te saca de la plataforma (WhatsApp/Telegram)', en: 'Moves you off-platform (WhatsApp/Telegram)',
          re: /(escribe|contacta|habla|anade|agrega|manda|envia)(me|nos|le)? .{0,30}(whatsapp|telegram|wa\.me|t\.me)|(write|message|contact|text|add|dm) (me|us) .{0,25}(whatsapp|telegram)|wa\.me\/|t\.me\/|escribeme al privado|mensajes? al privado|text me (at|on)|dm me for/ },
        { id: 'offplatform_mention', w: 1, skipIf: 'offplatform', skipHosts: /(^|\.)(whatsapp\.com|telegram\.org|t\.me)$/,
          es: 'Menciona WhatsApp/Telegram', en: 'Mentions WhatsApp/Telegram',
          re: /whatsapp|telegram/ },
        // Frases típicas de quien necesita convencerte de que no es una estafa.
        { id: 'reassure', w: 2, noWarn: true,
          es: 'Insiste en que "no es una estafa"', en: 'Insists it is "not a scam"',
          re: /no es (una )?(estafa|fraude|timo)|not a (scam|fraud)|100% (real|legal|legit)|sin estafas/ },
        { id: 'urgency', w: 1,
          es: 'Presión de urgencia', en: 'Urgency pressure',
          re: /ultimas (plazas|unidades|horas)|solo (hoy|por hoy)|actua (ahora|ya)|oferta (limitada|termina hoy)|expira (hoy|en \d+ horas)|plazas limitadas|no (dejes|pierdas) (pasar )?(esta|la) oportunidad|urgente|ultima oportunidad|caduca en \d+ (minutos|horas)|act now|limited (spots|time offer)|expires (today|soon|in \d+ hours)|last chance|hurry/ }
    ];


    // ── Contexto: avisos, noticias y consejos contra estafas no deben puntuar ──
    // Si cerca de la coincidencia hay una palabra de advertencia ("cuidado", "nunca",
    // "no existe", "la policía alerta"…), esa coincidencia se ignora. Excepción: si el
    // mismo contexto tiene "no es una estafa", se trata como señal, no como aviso.
    const WARN = /\b(cuidado|ojo|alerta|alertan|advierte|advierten|advertencia|desconfia|desconfiar|desconfien|no (existe|hay|te fies|caigas|garantiza)|nunca|jamas|evita|evitar|evitan|detecta|detectan|estafa|estafas|fraude|fraudes|suplanta|suplantan|scam|scams|phishing|beware|warns|warning|never|avoid|do not|don't|no guarantee|policia|guardia civil)\b/;
    const REASSURE = /no es (una )?(estafa|fraude|timo)|not a (scam|fraud)/;

    function hits(rule, text) {
        const g = new RegExp(rule.re.source, 'g');
        let m;
        while ((m = g.exec(text)) !== null) {
            if (m[0] === '') { g.lastIndex++; continue; }
            if (rule.noWarn) return true;
            const ctx = text.slice(Math.max(0, m.index - 90), m.index + m[0].length + 40)
                .replace(/(para|a fin de|con el fin de) evitar/g, '');
            if (!WARN.test(ctx) || REASSURE.test(ctx)) return true;
        }
        return false;
    }

    // ── Enlaces ──────────────────────────────────────────────────────────
    const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']);
    const BRANDS = ['linkedin', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix',
        'facebook', 'instagram', 'whatsapp', 'binance', 'coinbase', 'santander', 'bbva',
        'caixabank', 'correos', 'dhl', 'fedex'];
    const BRAND_ALLOW = new Set(['google-analytics.com']);
    // Dominios que reescriben enlaces: el texto visible NO coincide con el href y es normal.
    const REDIRECTORS = new Set(['lnkd.in', 'linkedin.com', 't.co', 'facebook.com', 'google.com',
        'bit.ly', 'youtu.be', 'goo.gl']);
    const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 't.ly', 'ow.ly']);
    // Terminaciones que son extensiones de archivo / tecnologías, no dominios en un texto de enlace.
    const NOT_TLD = new Set(['js', 'ts', 'py', 'md', 'json', 'zip', 'mov', 'exe', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
        'ppt', 'pptx', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'txt', 'csv', 'css', 'html', 'php', 'jsx', 'tsx', 'rs', 'sh', 'rb']);
    const RISKY_TLD = new Set(['top', 'xyz', 'click', 'icu', 'cfd', 'sbs', 'monster', 'rest', 'zip', 'mov']);

    function registrable(host) {
        const p = host.split('.').filter(Boolean);
        if (p.length <= 2) return host;
        const last = p[p.length - 1], prev = p[p.length - 2];
        return (last.length === 2 && SECOND_LEVEL.has(prev)) ? p.slice(-3).join('.') : p.slice(-2).join('.');
    }
    const labelOf = (reg) => reg.split('.')[0];

    function brandSpoof(host) {
        const reg = registrable(host);
        if (BRAND_ALLOW.has(reg)) return null;
        const label = labelOf(reg);
        const tokens = host.split(/[.-]/);
        const variants = [host, host.replace(/0/g, 'o'), host.replace(/1/g, 'l'),
            host.replace(/1/g, 'i'), host.replace(/rn/g, 'm'), host.replace(/vv/g, 'w'),
            host.replace(/ln/g, 'in')];
        for (const b of BRANDS) {
            if (label === b) continue;                       // dominio legítimo (amazon.es, google.com…)
            if (tokens.includes(b)) return b;                // amazon-seguridad.com, linkedin.com.verify.top
            for (let i = 1; i < variants.length; i++) {      // paypa1.com, amaz0n.es, linkedln.com
                if (variants[i] !== host && variants[i].split(/[.-]/).includes(b)) return b;
            }
        }
        return null;
    }

    function scoreLinks(links) {
        const found = new Map(); // id -> {w, example}
        const add = (id, w, ex) => { if (!found.has(id)) found.set(id, { w, example: ex }); };
        (links || []).slice(0, 150).forEach(l => {
            let u;
            try { u = new URL(l.href); } catch (e) { return; }
            if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
            const host = u.hostname.toLowerCase();
            const reg = registrable(host);
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || u.username) add('link_obfuscated', 3, host); // IP o usuario@: casi nunca es legítimo
            if (host.includes('xn--')) add('link_obfuscated', 2, host);
            if (SHORTENERS.has(reg)) add('link_shortener', 1, host);
            if (RISKY_TLD.has(host.split('.').pop()) && !BRAND_ALLOW.has(reg)) add('link_risky_tld', 1, host);
            const spoof = brandSpoof(host);
            if (spoof) add('link_brand_spoof', 3, host);
            // Texto visible que parece un dominio pero el enlace va a otro.
            // Solo si TODO el texto es un dominio (con ruta opcional): "Node.js docs", "e.g. X"
            // o "main.zip" no son dominios. Se descartan extensiones de archivo y TLD de 1 letra.
            const shown = (l.text || '').trim().toLowerCase();
            const m = shown.match(/^(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[\/?#]\S*)?$/);
            const shownTld = m ? m[1].split('.').pop() : '';
            if (m && shownTld.length >= 2 && !NOT_TLD.has(shownTld) && !REDIRECTORS.has(reg)) {
                const shownReg = registrable(m[1]);
                if (shownReg !== reg) add('link_mismatch', 3, `${shownReg} → ${reg}`);
            }
        });
        return found;
    }

    const LINK_LABELS = {
        link_obfuscated: { es: 'Enlace con IP, usuario@ o caracteres disfrazados', en: 'Link with IP, user@ or disguised characters' },
        link_shortener:  { es: 'Enlace acortado que oculta el destino', en: 'Shortened link hiding the destination' },
        link_risky_tld:  { es: 'Enlace a un dominio de riesgo (.top, .xyz…)', en: 'Link to a risky domain (.top, .xyz…)' },
        link_brand_spoof:{ es: 'Enlace que imita a una marca conocida', en: 'Link imitating a well-known brand' },
        link_mismatch:   { es: 'El texto del enlace dice una web pero lleva a otra', en: 'Link text shows one site but goes to another' }
    };

    const LEVELS = { yellowFrom: 3, redFrom: 6 };

    function evaluate(rawText, links, opts) {
        const host = String((opts && opts.host) || '').toLowerCase();
        const text = norm(rawText);
        const reasons = [];
        if (text.length >= 25) {
            const fired = new Set();
            TEXT_RULES.forEach(r => {
                if (r.skipIf && fired.has(r.skipIf)) return;
                if (r.skipHosts && host && r.skipHosts.test(host)) return;
                if (hits(r, text)) { fired.add(r.id); reasons.push({ id: r.id, w: r.w, es: r.es, en: r.en }); }
            });
        }
        scoreLinks(links).forEach((v, id) => {
            const lab = LINK_LABELS[id];
            reasons.push({ id, w: v.w, es: lab.es, en: lab.en, example: v.example });
        });
        reasons.sort((a, b) => b.w - a.w);
        const score = reasons.reduce((s, r) => s + r.w, 0);
        const level = score >= LEVELS.redFrom ? 'red' : (score >= LEVELS.yellowFrom ? 'yellow' : 'green');
        return { score, level, reasons };
    }

    root.ArgiraRules = { evaluate, scoreLinks, norm, LEVELS };
})(globalThis);
