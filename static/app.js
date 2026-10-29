const $ = id => document.getElementById(id);
let dirty = false;
let busy = false;
function summary() {
  const parts = $('subnet').value.split('/')[0].split('.');
  $('gateway').textContent = parts.length === 4 ? [...parts.slice(0, 3), Number(parts[3]) + 1].join('.') : '-';
  $('manual').hidden = $('dhcp').checked;
}
function message(text, error = false) {
  $('message').hidden = !text;
  $('message').textContent = text;
  $('message').className = error ? 'error' : 'success';
}
function render(status, reset = false) {
  if (!dirty || reset) {
    for (const key of ['uplink', 'downstream']) {
      $(key).replaceChildren();
      if (!status.interfaces.length) $(key).add(new Option('No physical interfaces found', ''));
      for (const link of status.interfaces) {
        $(key).add(new Option(`${link.name} · ${link.usb ? 'USB · ' : ''}${link.up ? 'Link up' : 'No link'}`, link.name));
      }
      $(key).value = status.config[key];
    }
    $('subnet').value = status.config.subnet;
    $('dhcp').checked = status.config.dhcp;
    $('protect_lan').checked = status.config.protect_lan !== false;
    $('allow_downstream').checked = status.config.allow_downstream !== false;
    summary();
  }
  const enabled = status.configured && !status.stopped;
  const active = enabled && status.active;
  $('badge').textContent = status.error ? 'Needs attention' : active ? 'Routing active' : enabled ? 'Restoring settings' : 'Ready to configure';
  $('badge').className = 'badge' + (active && !status.error ? ' active' : '');
  $('apply').textContent = active ? 'Save changes' : 'Apply and start';
  $('stop').hidden = !enabled;
  $('downstream').disabled = enabled;
  $('count').textContent = status.clients.length;
  $('clients').replaceChildren();
  for (const client of status.clients) {
    const row = document.createElement('div'); row.className = 'client';
    const name = document.createElement('strong'); name.textContent = client.hostname;
    const address = document.createElement('small'); address.textContent = client.address;
    row.append(name, address); $('clients').append(row);
  }
  if (!status.clients.length) {
    const p = document.createElement('p'); p.className = 'hint';
    p.textContent = 'No leases.'; $('clients').append(p);
  }
  if (status.error) message(status.error, true);
}
async function refresh() {
  if (busy) return;
  try {
    const response = await fetch('/status'); const status = await response.json();
    if (!response.ok) throw new Error(status.error);
    render(status);
  } catch (error) { message(error.message || 'Unable to read network status.', true); }
}
async function mutate(path, value) {
  busy = true; $('apply').disabled = true; $('stop').disabled = true;
  message('Applying network settings…');
  try {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json',
      'X-Router-Token': document.querySelector('meta[name="router-token"]').content}, body: JSON.stringify(value)});
    const status = await response.json(); if (!response.ok) throw new Error(status.error);
    dirty = false; render(status, true);
    message(path === '/stop' ? 'Stopped. Adapter isolated.' : 'Settings saved. Routing active.');
  } catch (error) { message(error.message || 'Unable to apply settings.', true); }
  finally { busy = false; $('apply').disabled = false; $('stop').disabled = false; }
}
$('settings').addEventListener('input', () => { dirty = true; summary(); });
$('settings').addEventListener('submit', event => { event.preventDefault(); mutate('/apply', {
  uplink: $('uplink').value, downstream: $('downstream').value, subnet: $('subnet').value, dhcp: $('dhcp').checked, protect_lan: $('protect_lan').checked, allow_downstream: $('allow_downstream').checked}); });
$('stop').addEventListener('click', () => mutate('/stop', {}));
refresh(); setInterval(refresh, 5000);
