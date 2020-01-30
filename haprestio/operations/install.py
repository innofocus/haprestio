import argparse, os, logging
from haprestio import app

def argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--install", "-i", help="Installs configuration files in <dir>")
    return parser.parse_args()

def install():
    print('/'.join(__file__.split('/')[0:-2]))

    # serviceability
    if 'UWSGI' in app.config and not app.config['UWSGI']:
        logging.info("Creating PID file.")
        fh = open(app.config['PID_FILE'], "w")
        fh.write(str(os.getpid()))
        fh.close()

arguments = argparser()