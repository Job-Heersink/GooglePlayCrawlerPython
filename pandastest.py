from __future__ import print_function

import os
import sys

import pandas as pd
from lxml import html

def main(argv):
    data = pd.read_csv("apps"+os.sep+"data"+os.sep+"images.csv", sep=',')
    print(data)


if __name__ == "__main__":
    main(sys.argv[1:])
