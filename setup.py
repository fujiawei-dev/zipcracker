'''
Date: 2020-12-22 11:29:49
LastEditors: Rustle Karl
LastEditTime: 2020-12-24 20:45:11
'''
import os.path

from setuptools import setup

'''
python setup.py sdist
pip install dist/zipcracker-0.0.2.tar.gz
python setup.py bdist_wheel
pip install twine
twine upload dist/*
'''

# What packages are required for this module to be executed?
requires = [
    'py7zr',
    'rarfile',
    'tqdm',
    'project-pkgs',
    'peewee',
]

# Import the README and use it as the long-description.
cwd = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(cwd, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='zipcracker',
    packages=['zipcracker'],
    version='0.0.2',
    license='BSD',
    author='Rustle Karl',
    author_email='fu.jiawei@outlook.com',
    description='通过字典暴力破解压缩文件',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords=['unzip'],

    # 必须附带的数据文件
    include_package_data=True,
    data_files=[('zipcracker', ["zipcracker/source.dat"])],

    entry_points={
        'console_scripts': [
            'zipcracker = zipcracker:zipcracker',
        ],
    },

    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=requires,
)
