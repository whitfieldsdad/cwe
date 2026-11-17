
from cwe import client
from cwe.constants import DEFAULT_JSON_INDENT

import click


@click.group()
@click.option('--verify-tls/--no-verify-tls', default=True, help='Verify TLS certificates.')
@click.pass_context
def main(ctx: click.Context, verify_tls: bool):
    ctx.obj = {
        'verify_tls': verify_tls,
    }


@main.command()
@click.argument('output_path')
@click.pass_context
def download(ctx: click.Context, output_path: str):
    """
    Download the latest version of the CWE XML file. 
    """
    client.download_weakness_catalog(
        output_path=output_path,
        verify_tls=ctx.obj['verify_tls'],
    )
    

@main.command()
@click.argument('input_path')
@click.argument('output_path')
@click.option('--indent', type=int, default=DEFAULT_JSON_INDENT, help='Indentation level for the output JSON.')
def convert(input_path: str, output_path: str, indent: int):
    """
    Convert the CWE XML file to JSON format.
    """
    client.convert_from_xml_to_json(
        input_path=input_path,
        output_path=output_path,
        indent=indent,
    )


if __name__ == "__main__":
    main()
