import argparse
import sys
from rich.console import Console
from rich.table import Table

# Importamos la lógica desde nuestro otro archivo
from src.hash_identifier import HashIdentifier, Confidence

console = Console()

def main():
    # 1. Configurar el lector de argumentos de consola
    parser = argparse.ArgumentParser(
        description="Hash Identifier - A CLI tool to detect cryptographic hash algorithms."
    )
    parser.add_argument(
        "-s", "--string", 
        type=str, 
        help="The hash string you want to identify"
    )
    
    args = parser.parse_args()
    identifier = HashIdentifier()

    # 2. Si no pasó un hash por argumento, pedirlo de forma interactiva
    target_hash = args.string
    if not target_hash:
        target_hash = console.input("[bold cyan]Enter the hash to analyze:[/bold cyan] ").strip()

    if not target_hash:
        console.print("[bold red]Error:[/bold red] No hash string provided.")
        sys.exit(1)

    # 3. Ejecutar la lógica de identificación
    results = identifier.identify(target_hash)

    # 4. Diseñar la tabla de resultados con Rich
    if not results:
        console.print("[yellow]No matching hash algorithms found.[/yellow]")
        return

    table = Table(title=f"Analysis Results for: {target_hash[:20]}...", show_header=True)
    table.add_column("Algorithm", style="bold white")
    table.add_column("Confidence", justify="center")
    table.add_column("Description", style="dim")

    for cand in results:
        # Dar formato de color según la confianza
        if cand.confidence == Confidence.HIGH:
            conf_style = "[bold green]HIGH[/bold green]"
        elif cand.confidence == Confidence.MEDIUM:
            conf_style = "[yellow]MEDIUM[/yellow]"
        else:
            conf_style = "[dim red]LOW[/dim red]"

        table.add_row(cand.name, conf_style, cand.description)

    # 5. Imprimir la tabla en la consola
    console.print(table)

if __name__ == "__main__":
    main()