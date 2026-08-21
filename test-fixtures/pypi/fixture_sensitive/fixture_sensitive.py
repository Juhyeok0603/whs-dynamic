from pathlib import Path


def read_fixture():
    return Path.home().joinpath('.aws', 'credentials').read_text(encoding='utf-8')
