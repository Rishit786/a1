from setuptools import find_packages, setup

with open("README.MD", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='pyaadhaar',
    packages=find_packages(),
    version='2.0.3',
    description='This library is built to ease the process of decoding aadhaar QR codes and XML. It supports old aadhaar QR codes, newly released Secure aadhaar QR codes and also Offline e-KYC XML.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Tanmoy Sarkar',
    author_email='ts741127@gmail.com',
    license='MIT',
    url="https://github.com/Tanmoy741127/pyaadhaar",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers ',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
    keywords='software development aadhaar e-kyc verification',
    python_requires='>=3.6',
    install_requires=[
        'numpy',
        'opencv-python',
        'Pillow',
        'zxing-cpp',
        'python-dateutil',
        'pytz',
        'six',
        'toml'
    ],
)
