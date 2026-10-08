"use strict";
(() => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get("token") || "";
  history.replaceState(null, "", "/");
  const el = id => document.getElementById(id);
  const start = el("start"), stop = el("stop");
  let busy = false, latest = null, sequence = 0, rendered = 0;
  const names = {idle:"Ready",running:"Running",draining:"Draining active work",pending:"Pending reconciliation",stopped:"Stopped",failed:"Run failed",budget_exhausted:"Budget complete",curriculum_exhausted:"Curriculum complete"};
  function controls() {
    const terminal = latest && ["budget_exhausted","curriculum_exhausted","pending"].includes(latest.state);
    start.disabled = busy || !latest || latest.active || latest.accepting || terminal;
    stop.disabled = busy || !latest || (!latest.active && !latest.accepting);
  }
  function render(s) {
    latest = s;
    el("state").textContent = names[s.state] || s.state;
    el("detail").textContent = s.detail || (s.state === "draining" ? "Dispatch is closed. Active work is finishing." : s.state === "pending" ? "Uncertain work is retained for reconciliation." : "The local worker owns this run.");
    el("orb").className = "orb " + s.state;
    el("epochs").textContent = s.completed_epochs ?? "—";
    el("epoch-limit").textContent = s.max_epochs !== undefined ? "Limit: " + s.max_epochs + " epochs" : "Bounded curriculum";
    el("tasks").textContent = s.completed_tasks;
    el("pending").textContent = s.pending_tasks + " pending";
    el("home-completed").textContent = s.home_completed !== undefined ? s.home_completed + " / " + (s.home_total ?? 50) : "—";
    el("home-first").textContent = s.home_first_correct ?? "—";
    el("home-final").textContent = s.home_final_correct ?? "—";
    el("calls").textContent = (s.coach_calls !== undefined && s.worker_calls !== undefined) ? s.coach_calls + s.worker_calls : "—";
    el("call-detail").textContent = (s.coach_calls !== undefined ? s.coach_calls : "—") + " coach / " + (s.worker_calls !== undefined ? s.worker_calls : "—") + " worker";
    el("elapsed").textContent = s.wall_seconds !== undefined ? Math.floor(s.wall_seconds / 60) + "m " + Math.floor(s.wall_seconds % 60) + "s" : "—";
    el("tokens").textContent = s.input_tokens !== undefined ? s.input_tokens.toLocaleString() + " in / " + (s.output_tokens ?? 0).toLocaleString() + " out" : "Token usage unavailable";
    el("run-id").textContent = s.run_id || "No run loaded";
    el("model").textContent = s.model || (s.model_running ? "Caller-owned gateway" : "Not running");
    el("worker").textContent = s.worker_pid ? "PID " + s.worker_pid + (s.active ? " · active" : " · idle") : "No active process";
    el("updated").textContent = "Updated " + new Date().toLocaleTimeString();
    el("connection").textContent = "Authenticated · local scope verified";
    controls();
  }
  async function call(action) {
    const request = ++sequence;
    if (!/^[0-9a-f]{64}$/.test(token)) throw new Error("Open XNET Dojo from its Desktop shortcut to authorize controls.");
    const response = await fetch("/api/" + action, {method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer " + token},body:"{}",cache:"no-store",signal:AbortSignal.timeout(5000)});
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error === "scope_rejected" ? "The control scope is unavailable or expired." : "Controller unavailable (" + (result.error || response.status) + ").");
    if (request >= rendered) {rendered = request; render(result.status);}
  }
  function failed(error) {
    el("connection").textContent = error.message;
    start.disabled = true; stop.disabled = true;
    if (!latest) {el("state").textContent = "Disconnected"; el("detail").textContent = "Waiting for the local controller.";}
  }
  async function act(action) {
    if (busy) return;
    busy = true; controls();
    let success = false;
    try {await call(action); success = true;} catch (error) {failed(error);} finally {busy = false; if (success) controls();}
  }
  start.addEventListener("click", () => act("start"));
  stop.addEventListener("click", () => act("stop"));
  async function poll() {
    if (!busy) {try {await call("status");} catch (error) {failed(error);}}
    setTimeout(poll, 2000);
  }
  poll();
})();
