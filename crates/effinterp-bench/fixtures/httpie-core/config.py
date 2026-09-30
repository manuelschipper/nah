from pathlib import Path


class BaseConfig:
    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        self.path.open()

    def save(self):
        self.path.write_text('config')


class Config(BaseConfig):
    pass
