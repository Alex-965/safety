// Password visibility is opt-in; fields stay masked until the user checks the box.
document.querySelectorAll('input[type="password"]').forEach((input, index) => {
  if (!input.id) input.id = `password-${index}`;
  const label = document.createElement('label');
  label.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:14px;margin:8px 0 12px';
  const toggle = document.createElement('input');
  toggle.type = 'checkbox';
  toggle.style.cssText = 'display:inline;width:16px;height:16px;margin:0;padding:0';
  toggle.setAttribute('aria-controls', input.id);
  toggle.addEventListener('change', () => { input.type = toggle.checked ? 'text' : 'password'; });
  label.append(toggle, document.createTextNode('Показати пароль'));
  input.insertAdjacentElement('afterend', label);
});
