# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess, os


class Deploy(install):

    def run(self):
        install.run(self)
        path_script = os.path.dirname(os.path.realpath(__file__))
        deploy_script = os.path.join(path_script, 'meta', 'meta.sh')
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

with open('haprestio/infos/version.txt') as f:
    version = f.read().split('.')
    version[2] = str(int(version[2]) + 1)
    f.close()

with open('haprestio/infos/version.txt', "w") as f:
    f.write('.'.join(version))
    f.close()

version_num=".".join(version[:3])
version_name=version[3]

subprocess.run('rm -rf build dist', shell=True)

data_files = [ '/'.join(x[0].split('/')[1:])+"/*" for x in os.walk('haprestio/files') ]
data_files.append('meta/*')
data_files.append('infos/*')

setup(
    name='haprestio',
    version=version_num,
    entry_points={"console_scripts": ['haprestio = haprestio.main:main']},
    description='rest api controlling haproxy on consul',
    long_description=readme,
    author='Caius Crypt',
    author_email='caius.crypt@gmail.com',
    url='https://github.com/innofocus/haprestio',
    license=license,
    include_package_data=True,
    package_data={'haprestio': data_files},
    install_requires=requirements,
    packages=find_packages(exclude=['tests', 'files'])
)
