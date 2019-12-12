# GooglePLayCrawlerPython
this project is based on https://github.com/egbertbouman/APKfetch


### Dependencies
* Python 3.6+
* requests
* protobuf
* PyCryptodome
* lxml

The Python packages can be installed with

    pip install -r requirements.txt


### Using the library

Using the library is as simple as:

```python
from APKfetch.apkfetch import APKfetch

def main():
  apk = APKfetch()
  apk.login('you@gmail.com', 'yourpassword', 'yourandroidid')
  apk.crawl('com.somepackage')

if __name__ == '__main__':
    main()
```


Note that you do need an androidid for this program to work, you can get an android id by installing Device ID on your android device.

### Using the CLI

```
usage: apkfetch.py [--help] [--user USER] [--passwd PASSWD]
                   [--androidid ANDROIDID] [--version VERSION]
                   [--package PACKAGE]

Fetch APK files from the Google Play store

optional arguments:
  --help, -h            Show this help message and exit
  --user USER, -u USER  Google username
  --passwd PASSWD, -p PASSWD
                        Google password
  --androidid ANDROIDID, -a ANDROIDID
                        AndroidID
  --version VERSION, -v VERSION
                        Download a specific version of the app
  --package PACKAGE, -k PACKAGE
                        Package name of the app
``` 
