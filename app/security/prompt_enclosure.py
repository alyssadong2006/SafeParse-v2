"""Create an unambiguous, single-use enclosure for untrusted text."""
import html
import secrets


def enclose(text: str):
    nonce = secrets.token_hex(8)
    tag = "untrusted_data_" + nonce
    # Escaping prevents the page from introducing markup that resembles our boundary.
    escaped = html.escape(text, quote=False)
    return "<{0}>\n{1}\n</{0}>".format(tag, escaped)
