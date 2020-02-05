import argparse

def argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--install", "-i", action="store_true", help="Installs configuration files in <INSTALL_DIR>")
    parser.add_argument("--install_dir", "-d",
                        help="Specifies the configuration files <INSTALL_DIR>", default="/etc/{}".format(__name__.split('.')[0]))
    return parser.parse_args()

args = argparser()