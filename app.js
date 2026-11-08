(() => {
  'use strict';
  const commands = {
    install: 'go install github.com/lilsadfoqs/azhaq/cmd/azhaq@latest',
    mcp: 'claude mcp add azhaq -- azhaq mcp -allow example.com -max-requests 5000',
    docker: 'docker pull ghcr.io/lilsadfoqs/azhaq'
  };
  const toast = document.getElementById('copy-status');
  let toastTimer;
  function announce(message) {
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.classList.add('visible');
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 2200);
  }
  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const previousFocus = document.activeElement;
      const field = document.createElement('textarea');
      field.value = text;
      field.setAttribute('readonly', '');
      field.style.cssText = 'position:fixed;top:0;left:-9999px';
      document.body.appendChild(field);
      field.select();
      const success = document.execCommand('copy');
      field.remove();
      previousFocus?.focus();
      if (!success) throw new Error('Clipboard unavailable');
    }
  }
  document.querySelectorAll('[data-copy]').forEach(button => {
    let iconTimer;
    const originalIcon = button.querySelector('use').getAttribute('href');
    button.addEventListener('click', async () => {
      try {
        await copy(commands[button.dataset.copy]);
        const icon = button.querySelector('use');
        clearTimeout(iconTimer);
        icon.setAttribute('href', '#az-check');
        announce('Command copied');
        iconTimer = setTimeout(() => icon.setAttribute('href', originalIcon), 1800);
      } catch {
        announce('Clipboard unavailable. Select the command to copy it.');
      }
    });
  });
  const captions = {
    'map-tab': 'v0.16.0 · local demo fixture',
    'roles-tab': 'v0.16.0 documentation example · VAmPI',
    'mcp-tab': 'MCP configuration · Claude Code'
  };
  document.querySelectorAll('[role="tablist"]').forEach(tablist => {
    const tabs = [...tablist.querySelectorAll('[role="tab"]')];
    function select(tab, focus = false) {
      tabs.forEach(item => {
        const active = item === tab;
        item.setAttribute('aria-selected', String(active));
        item.tabIndex = active ? 0 : -1;
        document.getElementById(item.getAttribute('aria-controls')).hidden = !active;
      });
      if (captions[tab.id]) document.getElementById('demo-caption-text').textContent = captions[tab.id];
      if (focus) tab.focus();
    }
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => select(tab));
      tab.addEventListener('keydown', event => {
        let next;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabs.length - 1;
        if (next !== undefined) { event.preventDefault(); select(tabs[next], true); }
      });
    });
  });
  document.querySelectorAll('[data-tooltip]').forEach(control => {
    control.addEventListener('keydown', event => {
      if (event.key === 'Escape') control.classList.add('tooltip-dismissed');
    });
    ['mouseleave', 'blur'].forEach(name => control.addEventListener(name, () => control.classList.remove('tooltip-dismissed')));
  });
  const themeButton = document.querySelector('.theme-toggle');
  function updateTheme() {
    const light = document.documentElement.dataset.theme === 'light';
    themeButton.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
    themeButton.dataset.tooltip = light ? 'Dark theme' : 'Light theme';
    themeButton.querySelector('use').setAttribute('href', light ? '#az-moon' : '#az-sun');
    document.querySelector('meta[name="theme-color"]').content = light ? '#fafaf9' : '#090909';
  }
  updateTheme();
  themeButton.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('azhaq-theme', next); } catch {}
    updateTheme();
  });
})();
