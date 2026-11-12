from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)


setup(name="demo", cmdclass={"install": PostInstall})
