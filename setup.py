# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess, os


class Deploy(install):

    def run(self):
        install.run(self)
        path_script = os.path.dirname(os.path.realpath(__file__))
        deploy_script = os.path.join(path_script, 'deploy', 'deploy.sh')
        subprocess.check_output([deploy_script, path_script])


with open('README.md') as f:
    readme = f.read()
    f.close()

with open('LICENSE') as f:
    license = f.read()
    f.close()

with open('requirements.txt') as f:
    requirements = f.readlines()
    f.close()

with open('version.txt') as f:
    version = f.read().split('.')
    version[2] = str(int(version[2]) + 1)
    f.close()

with open('version.txt', "w") as f:
    f.write('.'.join(version))
    f.close()

subprocess.run('rm -rf build dist', shell=True)

setup(
    name='Haprestio',
    version='.'.join(version),
    entry_points={"console_scripts": ['haprestio = Haprestio.haprestio:main']},
    description='rest api controlling haproxy on consul',
    long_description=readme,
    author='Caius Crypt',
    author_email='caius.crypt@gmail.com',
    url='https://github.com/innofocus/haprestio',
    license=license,
    include_package_data=True,
    package_data={'Haprestio': ['data/[!_]*', 'deploy/*']},
    install_requires=requirements,
    packages=find_packages(exclude=('tests'))
)
