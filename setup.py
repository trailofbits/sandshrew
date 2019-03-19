from setuptools import setup, find_packages

setup(
    name = "sandshrew",
    version = "0.0.1",
    url="https://github.com/trailofbits/sandshrew",
    entry_points = {
        'console_scripts': [
            'sandshrew=sandshrew.__main__:main'
        ],
    },
    install_requires=[
        'pyelftools',
        'manticore'
    ],
)
