"""
Unit tests for crawler and parser.
"""

from krypt.crawler.parser import HtmlParser


def test_html_parser_links_and_forms():
    html = """
    <html>
        <body>
            <a href="/about">About</a>
            <a href="https://external.com/page">External</a>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
            <script src="/static/app.js"></script>
        </body>
    </html>
    """
    parsed = HtmlParser.parse("http://example.local", html)
    assert "http://example.local/about" in parsed.links
    assert "https://external.com/page" in parsed.links
    assert "http://example.local/static/app.js" in parsed.scripts
    assert len(parsed.forms) == 1
    assert parsed.forms[0].method == "POST"
    assert parsed.forms[0].action == "http://example.local/login"
    assert "username" in parsed.parameters
    assert "password" in parsed.parameters
