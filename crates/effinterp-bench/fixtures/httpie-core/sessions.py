from pathlib import Path

from config import BaseConfig


def get_session(path):
    session = Session(path)
    session.load()
    return session


class Session(BaseConfig):
    def __init__(self, path):
        super().__init__(path=Path(path))
