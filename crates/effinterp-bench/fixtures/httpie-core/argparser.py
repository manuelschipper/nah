import argparse
import os


class HTTPieArgumentParser(argparse.ArgumentParser):
    def parse_args(self):
        os.environ.get('HTTPIE_PARSE')
        return super().parse_args()
