"use strict";

let token = "";
let licenses = [];
let resetRequests = [];
let selected = null;
const $ = id => document.getElementById(id);

function status(text, bad = false) {
  $("status").textContent = text;
  $("status").style.color = bad ? "#ff9eac" : "#77d6d0";
}

async function api(path, options = {}) {
  if (!token) throw Error("Conecte-se primeiro.");
  const response = await fetch(path, {
    ...options,
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    cache: "no-store",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(data.error || "Falha na operação");
  return data;
}

const expired = row => row.expires_at && new Date(row.expires_at) <= new Date();
const blocked = row => !!row.revoked_at || expired(row);
const date = value => value ? new Date(value).toLocaleString("pt-BR") : "Sem prazo";
const shortHash = value => value ? value.slice(0, 8) + "…" + value.slice(-6) : "—";

function cell(row, text) {
  const td = document.createElement("td");
  td.textContent = text;
  row.append(td);
  return td;
}

function renderLicenses() {
  const tbody = $("rows");
  tbody.replaceChildren();
  const query = $("search").value.trim().toLowerCase();
  const filter = $("filter").value;
  const visible = licenses.filter(row => [row.id, row.key, row.label, row.username]
    .some(value => String(value || "").toLowerCase().includes(query)) &&
    (filter === "all" || (filter === "active" && !blocked(row)) || (filter === "blocked" && blocked(row)) || (filter === "bound" && row.username)));

  $("total").textContent = token ? licenses.length : "—";
  $("active").textContent = token ? licenses.filter(row => !blocked(row)).length : "—";
  $("bound").textContent = token ? licenses.filter(row => row.username).length : "—";
  $("empty").hidden = visible.length > 0;
  $("empty").textContent = token ? "Nenhuma licença encontrada." : "Conecte-se para carregar as licenças.";

  for (const license of visible) {
    const row = document.createElement("tr");
    const keyCell = cell(row, "");
    const key = document.createElement("strong");
    const label = document.createElement("small");
    key.textContent = license.key || "Key antiga não recuperável";
    key.className = license.key ? "license-key" : "legacy-key";
    label.textContent = (license.label || "Sem identificação") + " · ID #" + license.id;
    keyCell.append(key, label);
    cell(row, license.username || "Não vinculada");
    cell(row, date(license.expires_at));
    const statusCell = cell(row, "");
    const badge = document.createElement("span");
    badge.className = "badge" + (blocked(license) ? " blocked" : "");
    badge.textContent = license.revoked_at ? "Banida" : expired(license) ? "Expirada" : "Ativa";
    statusCell.append(badge);
    const actions = cell(row, "");
    const button = document.createElement("button");
    button.className = "button ghost small";
    button.textContent = "Gerenciar";
    button.onclick = () => openDetails(license);
    actions.append(button);
    tbody.append(row);
  }
}

function renderResetRequests() {
  const host = $("reset-list");
  host.replaceChildren();
  const filter = $("reset-filter").value;
  const visible = resetRequests.filter(request => filter === "all" || request.status === filter);
  const pendingCount = resetRequests.filter(request => request.status === "pending").length;
  $("pending").textContent = token ? pendingCount : "—";
  $("reset-nav-count").textContent = pendingCount;
  if (!visible.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = token ? "Nenhum pedido neste filtro." : "Conecte-se para carregar os pedidos.";
    host.append(empty);
    return;
  }
  for (const request of visible) {
    const card = document.createElement("article");
    card.className = "reset-item";
    const info = document.createElement("div");
    const title = document.createElement("strong");
    const meta = document.createElement("small");
    const devices = document.createElement("code");
    title.textContent = request.username + " · " + (request.label || "Licença #" + request.license_id);
    meta.textContent = "Pedido #" + request.id + " · " + date(request.created_at);
    devices.textContent = shortHash(request.old_device_hash) + "  →  " + shortHash(request.new_device_hash);
    info.append(title, meta, devices);
    const side = document.createElement("div");
    const badge = document.createElement("span");
    badge.className = "badge reset-" + request.status;
    badge.textContent = { pending: "Pendente", approved: "Aprovado", rejected: "Recusado" }[request.status] || request.status;
    side.append(badge);
    if (request.status === "pending") {
      const approve = document.createElement("button");
      const reject = document.createElement("button");
      approve.className = "button primary small";
      reject.className = "button danger small";
      approve.textContent = "Aprovar";
      reject.textContent = "Recusar";
      approve.onclick = () => resolveReset(request.id, "approve");
      reject.onclick = () => resolveReset(request.id, "reject");
      side.append(approve, reject);
    }
    card.append(info, side);
    host.append(card);
  }
}

async function refresh() {
  [licenses, resetRequests] = await Promise.all([api("/v1/admin/keys"), api("/v1/admin/reset-requests")]);
  renderLicenses();
  renderResetRequests();
}

function openDetails(license) {
  selected = license;
  $("detail-title").textContent = license.label || "Licença #" + license.id;
  $("detail-key").textContent = license.key || "Indisponível: registro antigo armazenava apenas o hash";
  $("copy-detail-key").disabled = !license.key;
  const meta = $("detail-meta");
  meta.replaceChildren();
  for (const text of ["ID #" + license.id, "Conta: " + (license.username || "não vinculada"), "Validade: " + date(license.expires_at), "Último login: " + date(license.last_login)]) {
    const item = document.createElement("span");
    item.textContent = text;
    meta.append(item);
  }
  const box = $("specs");
  box.replaceChildren();
  const names = { system: "Sistema", os: "Windows", cpu: "Processador", gpu: "Placa de vídeo", ram: "Memória RAM", motherboard: "Placa-mãe", storage: "Armazenamento", display: "Tela" };
  if (license.device_specs && Object.keys(license.device_specs).length) {
    for (const [name, label] of Object.entries(names)) {
      if (!license.device_specs[name]) continue;
      const item = document.createElement("div");
      const caption = document.createElement("small");
      const value = document.createElement("strong");
      item.className = "spec";
      caption.textContent = label;
      value.textContent = license.device_specs[name];
      item.append(caption, value);
      box.append(item);
    }
  } else {
    const text = document.createElement("p");
    text.textContent = "Ainda não compartilhado pelo usuário.";
    box.append(text);
  }
  $("ban").textContent = license.revoked_at ? "Desbanir key" : "Banir key";
  $("rotate").textContent = license.key ? "Trocar key" : "Gerar key exibível";
  $("details").showModal();
}

async function action(path, body, message) {
  await api(path, { method: "POST", body: JSON.stringify(body || {}) });
  $("details").close();
  await refresh();
  status(message);
}

async function resolveReset(id, decision) {
  const label = decision === "approve" ? "aprovar" : "recusar";
  if (!confirm("Deseja " + label + " este pedido de reset?")) return;
  try {
    await api(`/v1/admin/reset-requests/${id}/${decision}`, { method: "POST", body: "{}" });
    await refresh();
    status(decision === "approve" ? "HWID atualizado para o novo computador." : "Pedido recusado.");
  } catch (error) {
    status(error.message, true);
  }
}

$("connect").onclick = async () => {
  token = $("token").value.trim();
  $("token").value = "";
  try { await refresh(); status("Conectado ao painel."); }
  catch (error) { token = ""; status(error.message, true); renderLicenses(); renderResetRequests(); }
};
$("token").onkeydown = event => { if (event.key === "Enter") $("connect").click(); };
$("logout").onclick = () => { token = ""; licenses = []; resetRequests = []; $("newkey").textContent = ""; $("copy").classList.add("hidden"); renderLicenses(); renderResetRequests(); status("Desconectado."); };
$("refresh").onclick = async () => { try { await refresh(); status("Lista atualizada."); } catch (error) { status(error.message, true); } };
$("search").oninput = renderLicenses;
$("filter").onchange = renderLicenses;
$("reset-filter").onchange = renderResetRequests;
$("close-details").onclick = () => $("details").close();
$("copy-detail-key").onclick = async () => { if (selected?.key) await navigator.clipboard.writeText(selected.key); status("Key copiada."); };
$("ban").onclick = async () => { if (!selected || !confirm(selected.revoked_at ? "Desbanir esta key?" : "Banir esta key?")) return; try { await action(`/v1/admin/keys/${selected.id}/${selected.revoked_at ? "unban" : "revoke"}`, {}, "Alteração salva."); } catch (error) { status(error.message, true); } };
$("reset").onclick = async () => { if (!selected || !confirm("Liberar o vínculo para o próximo login?")) return; try { await action(`/v1/admin/keys/${selected.id}/reset-device`, {}, "Dispositivo liberado."); } catch (error) { status(error.message, true); } };
$("rotate").onclick = async () => { if (!selected || !confirm("Gerar uma nova key? A key anterior deixará de funcionar para novos cadastros.")) return; try { const result = await api(`/v1/admin/keys/${selected.id}/rotate-key`, { method: "POST", body: "{}" }); $("details").close(); await refresh(); $("newkey").textContent = result.key; $("copy").classList.remove("hidden"); status("Nova key gerada: " + result.key); } catch (error) { status(error.message, true); } };
$("extend").onclick = async () => { if (!selected) return; const value = prompt("Adicionar quantos dias?", "30"); if (value === null) return; const days = Number(value); if (!Number.isInteger(days) || days < 1 || days > 3650) return status("Informe entre 1 e 3650 dias.", true); try { await action(`/v1/admin/keys/${selected.id}/extend`, { days }, "Validade atualizada."); } catch (error) { status(error.message, true); } };
$("rename").onclick = async () => { if (!selected) return; const label = prompt("Nova identificação:", selected.label || ""); if (label === null) return; try { await action(`/v1/admin/keys/${selected.id}/rename`, { label }, "Identificação atualizada."); } catch (error) { status(error.message, true); } };
$("create").onsubmit = async event => { event.preventDefault(); try { const result = await api("/v1/admin/keys", { method: "POST", body: JSON.stringify({ label: $("label").value, days: Number($("days").value) }) }); $("newkey").textContent = result.key; $("copy").classList.remove("hidden"); await refresh(); status("Key criada: " + result.key); } catch (error) { status(error.message, true); } };
$("copy").onclick = async () => { try { await navigator.clipboard.writeText($("newkey").textContent); status("Key copiada."); } catch { status("Selecione e copie a key manualmente.", true); } };

renderLicenses();
renderResetRequests();

