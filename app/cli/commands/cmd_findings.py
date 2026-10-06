"""CYBERWOLF Finding Inspection, Detail & Retesting CLI Commands (BDIE V2).

Commands:
  cyberwolf findings list [--target <T>] [--severity <S>] [--status <ST>] [--cve <C>]
  cyberwolf findings show <finding_id>
  cyberwolf findings search <query> [--severity <S>] [--status <ST>]
  cyberwolf findings evidence <finding_id>
  cyberwolf findings timeline <finding_id>
  cyberwolf findings retest <finding_id>
  cyberwolf findings explain <finding_id>
"""

import hashlib
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from app.services.finding_service import get_finding_service

console = Console()


def handle_findings(action: str = "list", finding_id: Optional[str] = None,
                    query: Optional[str] = None, target: Optional[str] = None,
                    severity: Optional[str] = None, status: Optional[str] = None,
                    cve: Optional[str] = None):
    """Router for all BDIE finding operations."""
    service = get_finding_service()

    # Route: SHOW / INSPECT
    if action == "show" or (action == "list" and finding_id and (finding_id.startswith("CW-") or finding_id.startswith("BUG-"))):
        fid = finding_id or action
        detail = service.get_finding_detail(fid)
        if not detail:
            console.print(f"[red]Finding with ID '{fid}' not found in database.[/red]")
            return

        fnd = detail["finding"]
        inv = detail.get("investigation", {})
        loc = detail.get("exact_location", {})
        sec_expl = inv.get("security_exploitation", {})

        console.print(f"\n[bold cyan]◈ BDIE VULNERABILITY INVESTIGATION: {fnd['id']} ◈[/bold cyan]\n")

        # 1. Header / Metadata Panel
        sev = (fnd.get("severity") or "INFO").upper()
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim white"
        }.get(sev, "white")

        t = Text()
        t.append(f"Title:         {fnd.get('title') or fnd.get('vulnerability')}\n", style="bold white")
        t.append(f"Severity:      [{sev}]", style=sev_color)
        t.append(f"  |  Confidence: {fnd.get('confidence', 'MEDIUM')}", style="bold magenta")
        t.append(f"  |  Risk Score: {fnd.get('risk_score', 'N/A')}/10.0\n", style="bold yellow")
        t.append(f"Status:        {fnd.get('status', 'OPEN')}", style="bold green" if fnd.get('status') == 'RESOLVED' else "bold blue")
        if fnd.get("retest_result"):
            t.append(f"  |  Retest Result: {fnd.get('retest_result')}", style="bold yellow")
        t.append("\n")

        if fnd.get("cve"):
            t.append(f"CVE:           {fnd.get('cve')}\n", style="magenta")
        if fnd.get("cwe"):
            t.append(f"CWE:           {fnd.get('cwe')}\n", style="dim magenta")
        if fnd.get("owasp_category"):
            t.append(f"OWASP:         {fnd.get('owasp_category')}\n", style="dim cyan")
        t.append(f"Source Tools:  {', '.join(fnd.get('source_tools', [fnd.get('source_tool', 'CYBERWOLF')]))}\n", style="dim")

        console.print(Panel(t, title="[bold]Finding Overview[/bold]", border_style="cyan"))

        # 2. EXACT LOCATION PANEL
        loc_text = Text()
        loc_summary = loc.get("summary") or fnd.get("url") or f"{fnd.get('target')}:{fnd.get('port')}"
        loc_text.append(f"Hierarchy:     {loc.get('hierarchy', 'N/A')}\n", style="bold green")
        loc_text.append(f"Resolved Loc:  {loc_summary}\n", style="white")
        if fnd.get("url"):
            loc_text.append(f"URL:           {fnd.get('url')}\n", style="cyan")
        if fnd.get("http_method"):
            loc_text.append(f"HTTP Method:   {fnd.get('http_method')}\n", style="cyan")
        if fnd.get("endpoint"):
            loc_text.append(f"Endpoint:      {fnd.get('endpoint')}\n", style="cyan")
        if fnd.get("parameter"):
            loc_text.append(f"Parameter:     {fnd.get('parameter')}\n", style="yellow")
        if fnd.get("port"):
            loc_text.append(f"Port/Protocol: {fnd.get('port')}/{fnd.get('protocol', 'tcp')} ({fnd.get('service', 'N/A')})\n", style="white")
        if fnd.get("source_file"):
            loc_text.append(f"Source Code:   {fnd.get('source_file')}:{fnd.get('source_line', '')}\n", style="yellow")
        if fnd.get("config_location"):
            loc_text.append(f"Config Area:   {fnd.get('config_location')}\n", style="yellow")

        console.print(Panel(loc_text, title="[bold]Exact Affected Location[/bold]", border_style="green"))

        # 3. OBSERVED VS VERIFIED BEHAVIOR
        obs_text = Text()
        obs_text.append("◈ OBSERVED BEHAVIOR (Detection):\n", style="bold cyan")
        obs_text.append(f"{fnd.get('observed_behavior') or fnd.get('evidence', 'No observation recorded.')}\n\n", style="white")
        obs_text.append("◈ VERIFIED BEHAVIOR (Authorized Active Probe):\n", style="bold yellow")
        obs_text.append(f"{fnd.get('verified_behavior') or 'Not independently probe-verified. Passive or scanner observation only.'}\n", style="white")
        console.print(Panel(obs_text, title="[bold]Observed vs Verified Behavior[/bold]", border_style="blue"))

        # 4. SECURITY EXPLOITATION ASSESSMENT & IMPACT
        sec_text = Text()
        sec_text.append(f"Exploitability Level: {sec_expl.get('level', fnd.get('exploitability_level', 'MEDIUM'))}\n", style="bold red")
        sec_text.append(f"Prerequisites:        {sec_expl.get('prerequisites', 'Network reachability to target host/port.')}\n", style="white")
        sec_text.append(f"Potential Impact:     {fnd.get('potential_impact') or 'Confidentiality, Integrity, or Availability exposure.'}\n", style="yellow")
        sec_text.append(f"Limitations:          {sec_expl.get('limitations', 'Non-destructive testing only.')}\n", style="dim")
        console.print(Panel(sec_text, title="[bold]Security Exploitation Assessment[/bold]", border_style="red"))

        # 5. REMEDIATION & VERIFICATION ROADMAP
        rem_text = Text()
        rem_text.append("◈ DEFENSIVE REMEDIATION:\n", style="bold green")
        rem_text.append(f"{fnd.get('remediation') or 'Standard vendor patching and configuration hardening.'}\n\n", style="white")
        rem_text.append("◈ VERIFICATION PROCEDURE:\n", style="bold cyan")
        rem_text.append(f"{fnd.get('verification_procedure') or 'Re-test endpoint with non-destructive authorized probe.'}\n", style="white")
        console.print(Panel(rem_text, title="[bold]Actionable Remediation & Retesting[/bold]", border_style="green"))
        console.print()

    # Route: EVIDENCE
    elif action == "evidence":
        if not finding_id:
            console.print("[red]Error: Finding ID required. Example: cyberwolf findings evidence BUG-2026-00017[/red]")
            return
        detail = service.get_finding_detail(finding_id)
        if not detail:
            console.print(f"[red]Finding with ID '{finding_id}' not found.[/red]")
            return

        ev_chain = detail.get("evidence_chain", [])
        console.print(f"\n[bold cyan]◈ EVIDENCE CHAIN OF CUSTODY: {finding_id} ({len(ev_chain)} items) ◈[/bold cyan]\n")

        if not ev_chain:
            console.print(f"[dim]No structured cryptographic evidence recorded for {finding_id}.[/dim]\n")
            return

        for idx, ev in enumerate(ev_chain, 1):
            e_text = Text()
            e_text.append(f"Evidence ID:    {ev.get('id')}\n", style="bold white")
            e_text.append(f"Source Tool:    {ev.get('tool_name')} (Run ID: {ev.get('tool_run_id', 'N/A')})\n", style="cyan")
            e_text.append(f"Type:           {ev.get('evidence_type', 'TOOL_OUTPUT')}\n", style="white")
            e_text.append(f"Timestamp:      {ev.get('timestamp')}\n", style="dim")

            recorded_hash = ev.get("hash_sha256") or ""
            output_raw = ev.get("output_excerpt") or ""
            computed_hash = hashlib.sha256(output_raw.encode("utf-8")).hexdigest() if output_raw else ""

            if recorded_hash and recorded_hash == computed_hash:
                e_text.append(f"SHA-256 Digest: {recorded_hash}\n", style="green")
                e_text.append("Integrity:      ✔ HASH VERIFIED (Chain of Custody Intact)\n", style="bold green")
            elif recorded_hash:
                e_text.append(f"SHA-256 Digest: {recorded_hash}\n", style="green")
                e_text.append("Integrity:      ✔ RECORDED\n", style="bold green")
            else:
                e_text.append("Integrity:      ⚠ UNHASHED\n", style="yellow")

            if ev.get("output_excerpt"):
                e_text.append("\nOutput Excerpt:\n", style="bold white")
                e_text.append(ev.get("output_excerpt"), style="dim green")

            console.print(Panel(e_text, title=f"[bold]Evidence #{idx} [{ev.get('id')}][/bold]", border_style="cyan"))
        console.print()

    # Route: TIMELINE
    elif action == "timeline":
        if not finding_id:
            console.print("[red]Error: Finding ID required. Example: cyberwolf findings timeline BUG-2026-00017[/red]")
            return
        tl = service.get_timeline(finding_id)
        events = tl if isinstance(tl, list) else (tl.get("events", []) if isinstance(tl, dict) else [])

        console.print(f"\n[bold cyan]◈ AUDIT TIMELINE: {finding_id} ({len(events)} events) ◈[/bold cyan]\n")

        if not events:
            console.print(f"[dim]No timeline events recorded for {finding_id}.[/dim]\n")
            return

        table = Table(box=None)
        table.add_column("Timestamp", style="dim", width=24)
        table.add_column("Event Type", style="bold cyan", width=18)
        table.add_column("Details", style="white", width=46)
        table.add_column("Actor", style="dim", width=16)

        for ev in events:
            e_type = ev.get("event_type") or ev.get("type", "EVENT")
            actor = ev.get("actor") or ev.get("changed_by") or ev.get("tested_by") or "system"
            det = ev.get("description")
            if not det:
                if e_type == "STATUS_CHANGE":
                    det = f"{ev.get('old_status')} ➔ {ev.get('new_status')}: {ev.get('reason', '')}"
                elif e_type == "RETEST":
                    det = f"Retest probe: {ev.get('result')} ({ev.get('notes', '')})"
                else:
                    det = str(ev)

            table.add_row(ev.get("timestamp", ""), e_type, det, actor)

        console.print(table)
        console.print()

    # Route: RETEST
    elif action == "retest":
        if not finding_id:
            console.print("[red]Error: Finding ID required. Example: cyberwolf findings retest BUG-2026-00017[/red]")
            return
        console.print(f"\n[bold cyan]◈ INITIATING AUTHORIZED RETEST: {finding_id} ◈[/bold cyan]\n")
        res = service.retest_finding(finding_id, actor="cli-operator")
        if not res.get("success"):
            console.print(f"[bold red]✘ Retest Failed:[/bold red] {res.get('error', 'Unknown error')}\n")
            return

        r_res = res.get("retest_result")
        res_color = "bold green" if r_res == "PASS" else ("bold red" if r_res == "FAIL" else "bold yellow")

        console.print(f"Retest Result:       [{res_color}]{r_res}[/{res_color}]")
        console.print(f"Previous Status:     {res.get('previous_status')}")
        console.print(f"New Status:          [bold cyan]{res.get('new_status')}[/bold cyan]")
        console.print(f"Evidence ID:         {res.get('evidence_id')}")
        console.print(f"Notes:               {res.get('notes')}\n")

    # Route: SEARCH
    elif action == "search":
        search_q = query or finding_id or ""
        results = service.search_findings(query=search_q, severity=severity, status=status, target=target, limit=100)
        console.print(f"\n[bold cyan]◈ SEARCH RESULTS ({len(results)} found for '{search_q}') ◈[/bold cyan]\n")
        _render_findings_table(results)

    # Route: EXPLAIN
    elif action == "explain":
        if not finding_id:
            console.print("[red]Error: Finding ID required. Example: cyberwolf findings explain BUG-2026-00017[/red]")
            return
        expl = service.explain_finding(finding_id, use_ai=True)
        if not expl:
            console.print(f"[red]Finding '{finding_id}' not found.[/red]")
            return

        console.print(f"\n[bold cyan]◈ 6-POINT REMEDIATION ADVISOR: {finding_id} ◈[/bold cyan]\n")
        obs = expl.get("observed_facts", {})
        sec = expl.get("security_analysis", {})
        act = expl.get("actionable_guidance", {})

        console.print(f"[bold white]1. What was detected:[/bold white] {obs.get('what_was_detected')}")
        console.print(f"[bold white]2. Why is it dangerous:[/bold white] {sec.get('why_dangerous')}")
        console.print(f"[bold white]3. Evidence:[/bold white] {obs.get('evidence')}")
        console.print(f"[bold white]4. Likely impact:[/bold white] {sec.get('likely_impact')}")
        console.print(f"[bold white]5. What should be fixed:[/bold white] {act.get('what_should_be_fixed')}")
        console.print(f"[bold white]6. How to verify:[/bold white] {act.get('how_to_verify')}\n")

    # Default Route: LIST
    else:
        findings = service.list_findings(target=target, severity=severity, status=status, cve=cve)
        console.print(f"\n[bold cyan]◈ SECURITY FINDINGS INVENTORY ({len(findings)}) ◈[/bold cyan]\n")
        _render_findings_table(findings)


def _render_findings_table(findings):
    """Helper to render a standardized Rich findings table."""
    table = Table(box=None)
    table.add_column("ID", style="bold cyan", width=18)
    table.add_column("Severity", width=10)
    table.add_column("Title / Vulnerability", style="bold white", width=30)
    table.add_column("Exact Location", style="dim", width=22)
    table.add_column("Risk", style="yellow", width=6)
    table.add_column("Status", width=12)
    table.add_column("Retest", width=8)

    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim white"
        }.get(sev, "white")

        title_display = (f.get("title") or f.get("vulnerability") or "")[:28]
        loc_display = (f.get("url") or f.get("endpoint") or (f"{f.get('target')}:{f.get('port')}" if f.get("port") else f.get("target", "")))[:20]
        retest_disp = f.get("retest_result") or "—"

        table.add_row(
            f["id"],
            f"[{sev_color}]{sev}[/{sev_color}]",
            title_display,
            loc_display,
            str(f.get("risk_score", 0.0)),
            f.get("status", "OPEN"),
            retest_disp
        )

    console.print(table)
    console.print(f"\n[dim]To inspect: cyberwolf findings show <ID> • To retest: cyberwolf findings retest <ID>[/dim]\n")
