from __future__ import print_function

import sys
import csv

def main(argv):

    with open("apps/reviews.csv", "w") as csvfile:
        file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        file.writerow(
            ['Pkgname', 'documentVersion','timestampMsec','starRating','comment','personId','name','image'])
        csvfile.close()

if __name__ == "__main__":
    main(sys.argv[1:])