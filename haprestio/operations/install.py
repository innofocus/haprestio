import os, logging, shutil
from haprestio import app

install_source = '/'.join(__file__.split('/')[0:-2])

def install(args):
    # setup in /etc

    # if in development mode, flask will rerun...
    if not os.path.exists(args.install_dir):
        shutil.copytree(install_source+'/data/', args.install_dir)
    else:
        logging.info("Install already done")

    # serviceability
    if 'UWSGI' in app.config and not app.config['UWSGI']:
        logging.info("Creating PID file.")
        fh = open(app.config['PID_FILE'], "w")
        fh.write(str(os.getpid()))
        fh.close()
