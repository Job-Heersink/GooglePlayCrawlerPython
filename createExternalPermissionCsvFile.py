from __future__ import print_function
import os
import sys
from lxml import html
import requests
import csv

def main(argv):

    with open("apps/externalpermissions.csv", "w") as csvfile:
        file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        file.writerow(["Pkgname","ExternalPermissions"])
        csvfile.close()

if __name__ == "__main__":
    main(sys.argv[1:])