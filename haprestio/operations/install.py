import os, logging, shutil, subprocess, re
from .. import config

install_source = '/'.join(__file__.split('/')[0:-2])

def cfgTemplate(config, source, target):
    with open(source,"rt") as file:
        template = file.readlines()
    file.close()
    result = []
    for l in template:
        if "=" in l:
            k = re.search("(\w*) *= *(.*)", l).group(1)
        else:
            k = None
        if k in config.keys():
            if isinstance(config[k], bool):
                result.append("{} = {}".format(k, str(config[k])))
            else:
                result.append("{} = '{}'".format(k, config[k]))
        else:
            if not k:
                result.append(l.split('\n')[0])
            else:
                result.append("#{}".format(l.split('\n')[0]))
    with open(target, "wt") as file:
        file.write("\n".join(result))
    file.close()


def install(install_dir, cfg=None, uwsgi=False):
    # setup in /etc

    # if in development mode, flask will rerun...
    if not os.path.exists(install_dir):
        shutil.copytree(install_source+'/files/', install_dir)
    else:
        logging.info("Install already made")

    if cfg == "dev":
        configDict = dict(vars(config.ConfigDev))
    elif cfg == "test":
        configDict = dict(vars(config.ConfigTest))
    else:
        configDict = dict(vars(config.Config))

    cfgTemplate(configDict,
                "{}/files/haprestio.cfg".format(install_source),
                "{}/haprestio.cfg".format(install_dir))

    # serviceability
    if uwsgi:
        logging.info("Creating PID file.")
        fh = open(app.config['PID_FILE'], "w")
        fh.write(str(os.getpid()))
        fh.close()

def deploy(basedir):
    logging.info(" running meta/deploy.sh for {}".format(basedir))
    subprocess.run('{}/meta/deploy.sh {}'.format('/'.join(__file__.split('/')[:-2]), basedir), shell=True)