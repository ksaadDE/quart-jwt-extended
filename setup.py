"""
Quart-JWT-Extended
------------------
Quart-Login provides jwt endpoint protection for Quart.
"""

from setuptools import setup
import versioneer


with open("README.md", "r") as f:
    long_description = f.read()


setup(
    name="Quart-JWT-Extended",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    url="https://github.com/greenape/quart-jwt-extended",
    license="MIT",
    author="Jonathan Gray",
    author_email="jono@nanosheep.net",
    description="Extended JWT integration with Quart",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=["quart", "jwt", "json web token"],
    packages=["quart_jwt_extended"],
    zip_safe=False,
    platforms="any",
    install_requires=[
        "Werkzeug>=1.0.0",  # Needed for SameSite cookie functionality
        "Quart>=0.11",
        "PyJWT>=1.6.4",
        "six",
    ],
    python_requires=">=3.7",
    extras_require={"asymmetric_crypto": ["cryptography >= 2.3"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
