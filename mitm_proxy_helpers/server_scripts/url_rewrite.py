"""
Redirect a URL to another URL

arguments:
partial_url: url to match with
new_url: full url to replace the matching request url with

example command line invocation:
./mitmdump -s --no-http2 url_rewrite.py
--set partial_url='http://www.google.com/somepath'
--set new_url='http://www.donaldjtrump.com/path'
--mode transparent --listen-port 8081

"""
from __future__ import print_function
from mitmproxy import ctx
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


def load(loader):
    loader.add_option(
        "partial_url", str, "",
        "url to match upon"
    )
    loader.add_option(
        "new_url", str, "",
        "url to replace with"
    )

def request(flow):
    if ctx.options.partial_url in flow.request.pretty_url:
        original_url = flow.request.pretty_url
        print("Matched URL for redirect: '{}'".format(original_url))
        ctx.log(flow.request.path)
        parsed_new_url = urlparse(ctx.options.new_url)
        flow.request.host = parsed_new_url.netloc
        flow.request.path = parsed_new_url.path
        flow.request.headers["Host"] = parsed_new_url.netloc
        print("Redirected url '{}' to '{}'.\n".format(
            original_url, ctx.options.new_url))
