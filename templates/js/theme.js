/* Concert admin portal: the theme picker. Loaded from <head>, before the
   stylesheets, so the saved theme is on <html> before the page paints.
   The themes are graphicle.dev's; css/portal-themes.css holds their colors. */
(() => {
    'use strict';

    // [id, name, dark]. dark sets data-bs-theme, so Bootstrap's own colors
    // (alerts, badges, toasts) match the page.
    const THEMES = [
        ['paper', 'Paper', 0], ['synthwave84', "Synthwave '84", 1], ['solarized-light', 'Solarized Light', 0], ['solarized-dark', 'Solarized Dark', 1],
        ['nord', 'Nord', 1], ['dracula', 'Dracula', 1], ['gruvbox-dark', 'Gruvbox Dark', 1], ['github-light', 'GitHub Light', 0], ['github-dark', 'GitHub Dark', 1],
        ['high-contrast', 'High contrast', 0]
    ];
    const KEY = 'concert.portal.theme';
    const AUTO = 'auto'; // nothing saved: follow the system, as graphicle.dev does
    const AUTO_LIGHT = 'paper';
    const AUTO_DARK = 'synthwave84';
    // The two themes the portal had before this picker.
    const LEGACY = { light: 'github-light', dark: 'synthwave84' };

    const root = document.documentElement;
    const media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    const byId = Object.fromEntries(THEMES.map((t) => [t[0], t]));

    function load() {
        let v = null;
        try { v = localStorage.getItem(KEY); } catch {}
        if (v && LEGACY[v]) {
            v = LEGACY[v];
            save(v);
        }
        return v && byId[v] ? v : AUTO;
    }

    function save(choice) {
        try {
            if (choice === AUTO) localStorage.removeItem(KEY);
            else localStorage.setItem(KEY, choice);
        } catch {}
    }

    let choice = load();

    function resolve(c) {
        if (c !== AUTO) return c;
        return media && media.matches ? AUTO_DARK : AUTO_LIGHT;
    }

    function apply() {
        const t = byId[resolve(choice)];
        root.setAttribute('data-gd-theme', t[0]);
        root.setAttribute('data-bs-theme', t[2] ? 'dark' : 'light');
        const label = document.getElementById('theme-name');
        if (label) label.textContent = choice === AUTO ? 'Match system' : t[1];
        const button = document.getElementById('theme-menu');
        if (button) button.setAttribute('aria-label', 'Theme: ' + (choice === AUTO ? 'match system, now ' + t[1] : t[1]));
        document.querySelectorAll('#theme-options [data-theme]').forEach((el) => {
            el.setAttribute('aria-checked', String(el.getAttribute('data-theme') === choice));
        });
    }

    function pick(c) {
        choice = byId[c] ? c : AUTO;
        save(choice);
        apply();
    }

    apply();

    if (media) {
        const onSystem = () => { if (choice === AUTO) apply(); };
        if (media.addEventListener) media.addEventListener('change', onSystem);
        else if (media.addListener) media.addListener(onSystem);
    }

    // Another tab picked a theme: follow it.
    window.addEventListener('storage', (e) => {
        if (e.key !== KEY && e.key !== null) return;
        choice = load();
        apply();
    });

    function item(id, name, swatchTheme) {
        const li = document.createElement('li');
        li.setAttribute('role', 'none');
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'dropdown-item';
        b.setAttribute('role', 'menuitemradio');
        b.setAttribute('data-theme', id);
        const sw = document.createElement('span');
        sw.className = 'gd-swatch' + (swatchTheme ? '' : ' gd-swatch-auto');
        if (swatchTheme) sw.setAttribute('data-gd-theme', swatchTheme);
        sw.setAttribute('aria-hidden', 'true');
        const check = document.createElement('i');
        check.className = 'bi bi-check2';
        check.setAttribute('aria-hidden', 'true');
        b.append(sw, document.createTextNode(name), check);
        b.addEventListener('click', () => pick(id));
        li.append(b);
        return li;
    }

    function header(text) {
        const li = document.createElement('li');
        li.setAttribute('role', 'presentation');
        const h = document.createElement('h6');
        h.className = 'dropdown-header';
        h.textContent = text;
        li.append(h);
        return li;
    }

    function divider() {
        const li = document.createElement('li');
        li.setAttribute('role', 'separator');
        const hr = document.createElement('hr');
        hr.className = 'dropdown-divider';
        li.append(hr);
        return li;
    }

    function buildMenu() {
        const menu = document.getElementById('theme-options');
        if (!menu) return;
        menu.replaceChildren(item(AUTO, 'Match system', null), divider(), header('Light'));
        THEMES.filter((t) => !t[2]).forEach((t) => menu.append(item(t[0], t[1], t[0])));
        menu.append(divider(), header('Dark'));
        THEMES.filter((t) => t[2]).forEach((t) => menu.append(item(t[0], t[1], t[0])));
        apply();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildMenu);
    else buildMenu();
})();
