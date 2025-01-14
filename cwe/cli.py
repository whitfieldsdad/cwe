from typing import Optional

import click

from cwe.client import DOWNLOAD_URL
from cwe import client


@click.group()
@click.option('--verify-tls/--no-verify-tls', default=True, help='Verify TLS certificates.')
@click.pass_context
def main(ctx: click.Context, verify_tls: bool):
    ctx.obj = {
        'verify_tls': verify_tls,
    }


@main.command()
@click.argument('output_path', default='cwec_latest.xml')
@click.pass_context
def download(ctx: click.Context, output_path: str):
    """
    Download the latest version of the CWE XML file. 
    """
    client.download(
        output_path=output_path,
        verify_tls_certificate_chain=ctx.obj['verify_tls'],
    )
    

@main.command()
@click.argument('input_path', default='cwec_latest.xml')
@click.argument('output_path', default='cwec_latest.json')
def convert(input_path: str, output_path: str):
    """
    Convert the CWE XML file to JSON format.
    """
    client.convert(
        input_path=input_path,
        output_path=output_path,
    )


if __name__ == "__main__":
    main()
