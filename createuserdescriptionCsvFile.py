from __future__ import print_function

import sys
import csv

def main(argv):

    with open("apps/userdescription.csv", "w") as csvfile:
        file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        file.writerow(
            ['Pkgname', 'backendPkgname', 'Title', 'Description', 'ShortDescription', 'Url', 'Genre', 'Type',
             'Price', 'CurrencyCode', 'Downloads', 'PGRating', 'AverageRating', 'RatingCount', 'FiveStarRatings', 'FourStarRatings',
             'ThreeStarRatings', 'TwoStarRatings', 'OneStarRatings', 'DeveloperAddress', 'DeveloperEmail',
             'DeveloperWebsite',
             'developerName', 'Creator', 'PrivacyPolicyLink', 'CurrentVersion', 'CurrentVersionString',
             'LastUpdated',
             'recentChanges', 'AndroidVersion', 'FileSize', 'isUnstable', 'hasInstantLink', 'containsAds'])
        csvfile.close()

if __name__ == "__main__":
    main(sys.argv[1:])