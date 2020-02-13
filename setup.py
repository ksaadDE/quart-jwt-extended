"""
Quart-JWT-Extended
------------------
Quart-Login provides jwt endpoint protection for Quart.
"""
import io
import re
from setuptools import setup

with io.open('quart_jwt_extended/__init__.py', encoding='utf-8') as f:
    version = re.search(r"__version__ = '(.+)'", f.read()).group(1)


with open("README.md", "r") as f:
    long_description = f.read()


setup(name='Quart-JWT-Extended',
      version=version,
      url='https://github.com/greenape/quart-jwt-extended',
      license='MIT',
      author='Landon Gilbert-Bland',
      author_email='landogbland@gmail.com',
      description='Extended JWT integration with Quart',
      long_description=long_description,
      long_description_content_type="text/markdown",
      keywords=['quart', 'jwt', 'json web token'],
      packages=['quart_jwt_extended'],
      zip_safe=False,
      platforms='any',
      install_requires=[
          'Werkzeug>=1.0.0',  # Needed for SameSite cookie functionality
          'Quart>=0.11',
          'PyJWT>=1.6.4',
          'six',
      ],
      extras_require={
        'asymmetric_crypto':  ["cryptography >= 2.3"]
      },
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
      ])
