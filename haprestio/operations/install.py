import argparse, os

def argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--install", "-i", help="Installs configuration files in <dir>")
    return parser.parse_args()

def install():
    print('/'.join(__file__.split('/')[0:-2]))
    print('ok')

arguments = argparser()