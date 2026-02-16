"""Command-line interface for Project Artemis."""

import asyncio
import json
import sys
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
    table.add_row("kql", "Coming Soon", "Microsoft Kusto Query Language")
    table.add_row("snort", "Coming Soon", "Network IDS rules")
    
    console.print(table)


@main.command()
@click.argument("rule_file", type=click.Path(exists=True))
@click.option("-f", "--format", "rule_format", default="sigma",
              type=click.Choice(["sigma", "yara", "splunk"]),
              help="Rule format")
def validate(rule_file: str, rule_format: str):
    """Validate an existing detection rule."""
    from artemis.generators import SigmaGenerator, YaraGenerator, SplunkGenerator
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


if __name__ == "__main__":
    main()
