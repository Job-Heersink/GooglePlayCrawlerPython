from __future__ import print_function

import os
import sys
import time
import argparse
from datetime import datetime

import requests
import csv
import logging

import apkfetch_pb2

from util import encrypt

ITERMAX = 500

DOWNLOAD_FOLDER_PATH = 'apps/'

GOOGLE_LOGIN_URL = 'https://android.clients.google.com/auth'
GOOGLE_CHECKIN_URL = 'https://android.clients.google.com/checkin'
GOOGLE_DETAILS_URL = 'https://android.clients.google.com/fdfe/details'
GOOGLE_BULKDETAILS_URL = 'https://android.clients.google.com/fdfe/bulkDetails'
GOOGLE_DELIVERY_URL = 'https://android.clients.google.com/fdfe/delivery'
GOOGLE_PURCHASE_URL = 'https://android.clients.google.com/fdfe/purchase'
GOOGLE_BROWSE_URL = 'https://android.clients.google.com/fdfe/browse'
GOOGLE_LIST_URL = 'https://android.clients.google.com/fdfe/list'
GOOGLE_REVIEWS_URL = "https://android.clients.google.com/fdfe/rev"
GOOGLE_FDFE_URL = "https://android.clients.google.com/fdfe"

LOGIN_USER_AGENT = 'GoogleLoginService/1.3 (gts3llte)'
MARKET_USER_AGENT = 'Android-Finsky/5.7.10 (api=3,versionCode=80371000,sdk=24,device=falcon_umts,hardware=qcom,product=falcon_reteu,platformVersionRelease=4.4.4,model=XT1032,buildId=KXB21.14-L1.40,isWideScreen=0)'
CHECKIN_USER_AGENT = 'Android-Checkin/2.0 (gts3llte)'
DOWNLOAD_USER_AGENT = 'AndroidDownloadManager/9 (Linux; U; Android 9; XT1032 Build/KXB21.14-L1.40)'


def num_to_hex(num):
    hex_str = format(num, 'x')
    length = len(hex_str)
    return hex_str.zfill(length + length % 2)


class APKfetch(object):

    def __init__(self):
        self.session = requests.Session()
        self.user = self.passwd = self.androidid = self.token = self.auth = None
        self.iter = 0

    def request_service(self, service, app, user_agent=LOGIN_USER_AGENT):
        """
        requesting a login service from google
        @service: the service to request, like ac2dm
        @app: the app to request to
        @user_agent: the user agent
        """

        self.session.headers.update({'User-Agent': user_agent,
                                     'Content-Type': 'application/x-www-form-urlencoded'})

        if self.androidid:
            self.session.headers.update({'device': self.androidid})

        data = {'accountType': 'HOSTED_OR_GOOGLE',
                'has_permission': '1',
                'add_account': '1',
                'get_accountid': '1',
                'service': service,
                'app': app,
                'source': 'android',
                'Email': self.user}

        if self.androidid:
            data['androidId'] = self.androidid

        data['EncryptedPasswd'] = self.token or encrypt(self.user, self.passwd)

        response = self.session.post(GOOGLE_LOGIN_URL, data=data, allow_redirects=True)
        response_values = dict([line.split('=', 1) for line in response.text.splitlines()])

        if 'Error' in response_values:
            error_msg = response_values.get('ErrorDetail', None) or response_values.get('Error')
            if 'Url' in response_values:
                error_msg += '\n\nTo resolve the issue, visit: ' + response_values['Url']
                error_msg += '\n\nOr try: https://accounts.google.com/b/0/DisplayUnlockCaptcha'
            raise RuntimeError(error_msg)
        elif 'Auth' not in response_values:
            raise RuntimeError('Could not login')

        return response_values.get('Token', None), response_values.get('Auth')

    def login(self, user, passwd, androidid=None):
        """
        login using googles as2dm authentication system
        @user: email
        @passwd: password
        @androidid: android id
        """

        self.user = user
        self.passwd = passwd
        self.androidid = androidid

        self.token, self.auth = self.request_service('ac2dm', 'com.google.android.gsf')

        logging.info('token: ' + self.token)

        _, self.auth = self.request_service('androidmarket', 'com.android.vending', MARKET_USER_AGENT)
        logging.info('auth: ' + self.auth)

        return self.auth is not None

    def details(self, package_name):
        """
        performs a GET request to get the details of a specific app
        @package_name: the app to get details from
        """

        headers = {'X-DFE-Device-Id': self.androidid,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'User-Agent': MARKET_USER_AGENT}

        params = {'doc': package_name}
        response = self.session.get(GOOGLE_DETAILS_URL, params=params, headers=headers, allow_redirects=True)

        details_response = apkfetch_pb2.ResponseWrapper()
        details_response.ParseFromString(response.content)
        # print(details_response.payload.detailsResponse.docV2)
        details = details_response.payload.detailsResponse.docV2
        if not details:
            logging.error('Could not get details for: ' + package_name)
        if details_response.commands.displayErrorMessage != "":
            logging.error(
                'error getting details: ' + details_response.commands.displayErrorMessage + " for: " + package_name)
        return details

    def reviews(self, package_name, amount=50):
        """
        performs a GET request to get the reviews of a specific app
        @package_name: the app to get reviews from
        @amount: amount of reviews to get
        """

        headers = {'X-DFE-Device-Id': self.androidid,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'User-Agent': MARKET_USER_AGENT}

        params = {'doc': package_name,
                  'n': amount}
        response = self.session.get(GOOGLE_REVIEWS_URL, params=params, headers=headers, allow_redirects=True)

        review_response = apkfetch_pb2.ResponseWrapper()
        review_response.ParseFromString(response.content)

        if not review_response:
            logging.error('Could not get reviews for: ' + package_name)
        if review_response.commands.displayErrorMessage != "":
            logging.error(
                'error getting reviews: ' + review_response.commands.displayErrorMessage + " for: " + package_name)
        return review_response.payload.reviewResponse.getResponse

    def get_download_url(self, package_name, version_code):
        """
        performs a GET request to get the download url of a specific app
        @package_name: the app to get the download url from
        @version_code: the version of the app to download
        """

        headers = {'X-DFE-Device-Id': self.androidid,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}

        data = {'doc': package_name,
                'ot': '1',
                'vc': version_code}

        response = self.session.get(GOOGLE_DELIVERY_URL, params=data, verify=True, headers=headers,
                                    allow_redirects=True)

        delivery_response = apkfetch_pb2.ResponseWrapper()
        delivery_response.ParseFromString(response.content)

        if not delivery_response:
            logging.error('Could not get download url for: ' + package_name)
        if delivery_response.commands.displayErrorMessage != "":
            logging.error(
                'error getting download url: ' + delivery_response.commands.displayErrorMessage + " for: " + package_name)
        return delivery_response.payload.deliveryResponse.appDeliveryData.downloadUrl

    def purchase(self, package_name, version_code):
        """
        performs a GET request to get the download token of a specific app and complete the purchase
        @package_name: the app to get the download token from
        @version_code: the version of the app to get the download token from
        """

        if version_code is None:
            raise RuntimeError('no version code for purchase')

        headers = {
            "X-DFE-Encoded-Targets": "CAEScFfqlIEG6gUYogFWrAISK1WDAg+hAZoCDgIU1gYEOIACFkLMAeQBnASLATlASUuyAyqCAjY5igOMBQzfA/IClwFbApUC4ANbtgKVAS7OAX8YswHFBhgDwAOPAmGEBt4OfKkB5weSB5AFASkiN68akgMaxAMSAQEBA9kBO7UBFE1KVwIDBGs3go6BBgEBAgMECQgJAQIEAQMEAQMBBQEBBAUEFQYCBgUEAwMBDwIBAgOrARwBEwMEAg0mrwESfTEcAQEKG4EBMxghChMBDwYGASI3hAEODEwXCVh/EREZA4sBYwEdFAgIIwkQcGQRDzQ2fTC2AjfVAQIBAYoBGRg2FhYFBwEqNzACJShzFFblAo0CFxpFNBzaAd0DHjIRI4sBJZcBPdwBCQGhAUd2A7kBLBVPngEECHl0UEUMtQETigHMAgUFCc0BBUUlTywdHDgBiAJ+vgKhAU0uAcYCAWQ/5ALUAw1UwQHUBpIBCdQDhgL4AY4CBQICjARbGFBGWzA1CAEMOQH+BRAOCAZywAIDyQZ2MgM3BxsoAgUEBwcHFia3AgcGTBwHBYwBAlcBggFxSGgIrAEEBw4QEqUCASsWadsHCgUCBQMD7QICA3tXCUw7ugJZAwGyAUwpIwM5AwkDBQMJA5sBCw8BNxBVVBwVKhebARkBAwsQEAgEAhESAgQJEBCZATMdzgEBBwG8AQQYKSMUkAEDAwY/CTs4/wEaAUt1AwEDAQUBAgIEAwYEDx1dB2wGeBFgTQ",
            "User-Agent": MARKET_USER_AGENT,
            'X-DFE-Device-Id': self.androidid,
            "X-DFE-Client-Id": "am-android-google",
            'Host': 'android.clients.google.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            "X-DFE-MCCMNC": "310260",
            "X-DFE-Network-Type": "4",
            "X-DFE-Content-Filters": "",
            "X-DFE-Request-Params": "timeoutMs=4000",
            'Authorization': 'GoogleLogin Auth=' + self.auth,
            'Accept-Encoding': '',
        }

        params = {'ot': 1,
                  'doc': package_name,
                  'vc': version_code}

        response = requests.post(GOOGLE_PURCHASE_URL, headers=headers,
                                 params=params, verify=True,
                                 timeout=60)

        response = apkfetch_pb2.ResponseWrapper.FromString(response.content)
        if response.commands.displayErrorMessage != "":
            logging.error(
                'error performing purchase: ' + response.commands.displayErrorMessage + " for: " + package_name)
        else:
            downloadtoken = response.payload.buyResponse.downloadToken
            return downloadtoken

    def fetch(self, package_name, version_code, apk_fn=None):
        """
        download the app, by getting a download url.
        @package_name: the app to download
        @version_code: the version of the app to download
        @apk_fn: predefined name, package_name by default
        """

        url = self.get_download_url(package_name, version_code)
        if not url:
            return 0

        response = self.session.get(url, headers={'User-Agent': DOWNLOAD_USER_AGENT},
                                    stream=True, allow_redirects=True)

        logging.info("downloading...")
        apk_fn = apk_fn or (DOWNLOAD_FOLDER_PATH + package_name + '.apk')
        if os.path.exists(apk_fn):
            os.remove(apk_fn)

        with open(apk_fn, 'wb') as fp:
            for chunk in response.iter_content(chunk_size=5 * 1024):
                if chunk:
                    fp.write(chunk)
                    fp.flush()
            fp.close()

        return os.path.exists(apk_fn)

    def getrelated(self, browsestream):
        """
        get the list of apps under the "more you might like" section under app details
        @browsestream: the link from the app details to request the list of related apps
        """

        headers = {'X-DFE-Device-Id': self.androidid,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'User-Agent': MARKET_USER_AGENT}

        response = self.session.get(GOOGLE_FDFE_URL + "/" + browsestream, params=None, headers=headers,
                                    allow_redirects=True)

        related_response = apkfetch_pb2.ResponseWrapper()
        related_response.ParseFromString(response.content)
        # print(related_response.preFetch[0].response.payload.listResponse.doc)

        if not related_response:
            logging.error('Could not get related apps for')
        if related_response.commands.displayErrorMessage != "":
            logging.error('error getting related apps: ' + related_response.commands.displayErrorMessage)
        return related_response.preFetch[0].response.payload.listResponse.doc[0]

    def loadvisitedapps(self):
        """
        load all apps previously visited from the appinfo.csv file
        """

        with open("apps/appinfo.csv", "r") as csvfile:
            file = csv.reader(csvfile, delimiter=',', quotechar='"')
            visitedapps = []

            for row in file:
                visitedapps += [row[0]]

            csvfile.close()

        visitedapps.pop(0)
        return visitedapps

    def store(self, details, reviews):
        """
        store the details and reviews of an app into a .csv file
        @details: the list of details of a specific app
        @reviews: the list of reviews from a specific app
        """

        with open("apps/appinfo.csv", "a") as csvfile:
            file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            file.writerow([details.docid, details.backendDocid, details.title, details.descriptionHtml,
                           details.descriptionShort,
                           "https://play.google.com/store/apps/details?" + details.docid + "&hl=en", "!TODO GENRE!",
                           details.details.appDetails.appType,
                           details.offer[0].micros, details.offer[0].currencyCode,
                           details.details.appDetails.numDownloads, details.relatedLinks.rated.label,
                           details.aggregateRating.starRating, details.aggregateRating.ratingsCount,
                           details.aggregateRating.fiveStarRatings,
                           details.aggregateRating.fourStarRatings, details.aggregateRating.threeStarRatings,
                           details.aggregateRating.twoStarRatings, details.aggregateRating.oneStarRatings,
                           details.details.appDetails.developerAddress,
                           details.details.appDetails.developerEmail, details.details.appDetails.developerWebsite,
                           details.details.appDetails.developerName, details.creator,
                           details.relatedLinks.privacyPolicyUrl,
                           details.details.appDetails.versionCode, details.details.appDetails.versionString,
                           details.details.appDetails.uploadDate,
                           details.details.appDetails.recentChangesHtml, "!!!",
                           details.details.appDetails.installationSize, details.details.appDetails.unstable,
                           details.details.appDetails.hasInstantLink, details.details.appDetails.containsAds])
            csvfile.close()

        with open("apps/permissions.csv", "a") as csvfile:
            with open("templatePermissions.csv", "r") as permissionsFile:
                permissions = csv.reader(permissionsFile, delimiter=',', quotechar='"')
                file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                haspermission = [details.docid]
                for row in permissions:
                    if row[0] in details.details.appDetails.permission:
                        haspermission += [1]
                    else:
                        haspermission += [0]

                file.writerow(haspermission)
                permissionsFile.close()
            csvfile.close()

        with open("apps/externalpermissions.csv", "a") as csvfile:
            file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            externalpermissions = [details.docid]
            for row in details.details.appDetails.permission:
                if not row.startswith("android.permission."):
                    externalpermissions += [row]

            file.writerow(externalpermissions)
            csvfile.close()

        # TODO implement technical

        with open("apps/images.csv", "a") as csvfile:
            file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            imageurls = [details.docid]
            for image in details.image:
                imageurls += [image.imageUrl]

            file.writerow(imageurls)
            csvfile.close()

        with open("apps/reviews.csv", "a") as csvfile:
            file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

            for data in reviews.review:
                file.writerow([details.docid, data.documentVersion, data.timestampMsec, data.starRating, data.comment,
                               data.userProfile.personId, data.userProfile.name, data.userProfile.image[0].imageUrl])

            csvfile.close()

    def crawl(self, package_name, visitedpackages=[]):
        """
        crawls throught the google play store, provided with a starting package
        @package_name: the package to start from
        @visitedpackages: a list of packages already visited
        """
        time.sleep(1)
        logging.info("started crawling through " + package_name + " on iteration: {}".format(self.iter))
        print("started crawling through " + package_name + " on iteration: {}".format(self.iter))
        details = self.details(package_name)
        version = details.details.appDetails.versionCode
        reviews = self.reviews(package_name)

        # TODO can even get more related links like similar apps, more from spotify etc

        self.store(details, reviews)

        if details.offer[0].micros == 0:
            if self.purchase(package_name, version):
                logging.info("successful purchase")
            if self.fetch(package_name, version):
                logging.info('Downloaded version {}'.format(version))
        else:
            logging.warning("This app needs to be paid for in order to download")

        relatedapps = self.getrelated(details.relatedLinks.youMightAlsoLike.url2)
        for app in relatedapps.child:
            if app.docid not in visitedpackages and self.iter < ITERMAX:
                self.iter += 1
                visitedpackages += [app.docid]
                self.crawl(app.docid, visitedpackages)


def main(argv):
    # parse arguments
    parser = argparse.ArgumentParser(add_help=False, description=(
        'Download APK files from the google play store and retrieve their information'))
    parser.add_argument('--help', '-h', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit')
    parser.add_argument('--user', '-u', help='Google username')
    parser.add_argument('--passwd', '-p', help='Google password')
    parser.add_argument('--androidid', '-a', help='AndroidID')
    parser.add_argument('--package', '-k', help='Package name of the app')
    parser.add_argument('--version', '-v', help='Download a specific version of the app')

    # prepare logging file
    logging.basicConfig(filename=datetime.now().strftime("logs/%Y-%m-%d_%H:%M:%S.log"), level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s")

    try:
        # assign parsed values
        args = parser.parse_args(sys.argv[1:])

        user = args.user
        passwd = args.passwd
        androidid = args.androidid
        package = args.package
        #version = args.version

        if not user or not passwd or not package or not androidid:
            parser.print_usage()
            raise ValueError('user, passwd, androidid and package are required options. android ID can be found using '
                             'Device id (playstore) on your android device')

            # create class
        apk = APKfetch()

        print("crawling through the playstore")

        # login
        apk.login(user, passwd, androidid)

        if not androidid and apk.androidid:
            print('AndroidID', apk.androidid)

        time.sleep(1)

        visitedapps = apk.loadvisitedapps()
        if package not in visitedapps:
            apk.crawl(package, visitedapps)

        print("finished crawling")


    except Exception as e:
        print('Error:', str(e))
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
