import os, logging, shutil, subprocess
from haprestio import app

install_source = '/'.join(__file__.split('/')[0:-2])

def templates(args):
    # setup in /etc

    # if in development mode, flask will rerun...
    if not os.path.exists(args.install_dir):
        shutil.copytree(install_source+'/files/', args.install_dir)
    else:
        logging.info("Install already done")

    # serviceability
    if 'UWSGI' in app.config and not app.config['UWSGI']:
        logging.info("Creating PID file.")
        fh = open(app.config['PID_FILE'], "w")
        fh.write(str(os.getpid()))
        fh.close()

def deploy():
    subprocess.run('/'.join(__file__.split('/')[:-2])+'/meta/deploy.sh')