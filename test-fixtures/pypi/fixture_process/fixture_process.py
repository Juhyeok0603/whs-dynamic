import subprocess
from pathlib import Path


def main():
    Path('/tmp/fixture-process.txt').write_text('harmless fixture\n', encoding='utf-8')
    subprocess.run(['python', '-c', 'print("fixture child")'], check=True)


if __name__ == '__main__':
    main()
