import os
import requests

from cli_definition import parser
from config import Config
from downloads import Downloader
from sessions import get_session
from transport import build_session
from update import check_updates


def raw_main(parser, main_program):
    args = parser.parse_args()
    return main_program(args)


def main():
    return raw_main(parser=parser, main_program=program)


def program(args):
    config = Config('/cfg/config.json')
    config.load()
    config.save()
    session = None
    if args.session:
        session = get_session('/cfg/session.json')
    if session:
        session.save()
    requests_session = build_session()
    request = requests.Request('GET', 'https://api.example.test/items').prepare()
    requests_session.send(request)
    Downloader().start()
    with open('/upload.bin', 'rb'):
        pass
    os.environ.get('HTTPIE_TOKEN')
    check_updates()
