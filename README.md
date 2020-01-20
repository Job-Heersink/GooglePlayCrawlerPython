# GooglePlayCrawlerPython
this project is based on https://github.com/egbertbouman/APKfetch


### Dependencies
* Python 3.6+
* requests
* protobuf
* PyCryptodome
* lxml

The Python packages can be installed with

    pip install -r requirements.txt


Note that you do need an androidid for this program to work, you can get an android id by installing Device ID on your android device.

### Using the CLI

```
usage: googleplaycrawler.py [--help] [--user USER] [--passwd PASSWD]
                            [--androidid ANDROIDID] [--package PACKAGE]
                            [--iterations ITERATIONS]

Download APK files from the google play store and retrieve their information

optional arguments:
  --help, -h            Show this help message and exit
  --user USER, -u USER  Google username
  --passwd PASSWD, -p PASSWD
                        Google password
  --androidid ANDROIDID, -a ANDROIDID
                        AndroidID
  --package PACKAGE, -k PACKAGE
                        Package name of the app
  --iterations ITERATIONS, -i ITERATIONS
                        Amount of apps you want to crawl through


``` 
