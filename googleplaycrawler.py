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
from lxml import html

# tweak these values according to your needs #
DOWNLOAD_APPS = True  # should the crawler download the apk files?
STORE_INFO = True  # should the crawler store the information in the .csv files?
NO_DUPLICATE_DATA = True  # whether the app should check if the starting app is crawled through or not using the .csv files
REVIEWS = 50  # amount of reviews to get per app
WAIT = 1  # seconds to wait before crawling the next app

DOWNLOAD_FOLDER_PATH = 'apps'+os.sep

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


class GooglePlayCrawler(object):

    def __init__(self):
        self.session = requests.Session()
        self.user = self.password = self.android_id = self.token = self.auth = None
        self.iter = 0

    def request_service(self, service, app, user_agent=LOGIN_USER_AGENT):
        """
        requesting a login service from google
        :param service: the service to request, like ac2dm
        :param app: the app to request to
        :param user_agent: the user agent
        :return: The response from the server
        """

        self.session.headers.update({'User-Agent': user_agent,
                                     'Content-Type': 'application/x-www-form-urlencoded'})

        if self.android_id:
            self.session.headers.update({'device': self.android_id})

        data = {'accountType': 'HOSTED_OR_GOOGLE',
                'has_permission': '1',
                'add_account': '1',
                'get_accountid': '1',
                'service': service,
                'app': app,
                'source': 'android',
                'Email': self.user}

        if self.android_id:
            data['androidId'] = self.android_id

        data['EncryptedPasswd'] = self.token or encrypt(self.user, self.password)

        response = self.session.post(GOOGLE_LOGIN_URL, data=data, allow_redirects=True)
        response_values = dict([line.split('=', 1) for line in response.text.splitlines()])

        if 'Error' in response_values:
            error_msg = response_values.get('ErrorDetail', None) or response_values.get('Error')
            if 'Url' in response_values:
                error_msg += '\n\nTo resolve the issue, visit: ' + response_values['Url']
                error_msg += '\n\nOr try: https://accounts.google.com/b/0/DisplayUnlockCaptcha'
            raise Exception(error_msg)
        elif 'Auth' not in response_values:
            raise Exception('Could not login')

        return response_values.get('Token', None), response_values.get('Auth')

    def login(self, user, password, android_id=None):
        """
        login using google's as2dm authentication system
        :param user: email
        :param password: password
        :param android_id: android id
        :return: True if the login was successful, False otherwise
        """

        self.user = user
        self.password = password
        self.android_id = android_id

        self.token, self.auth = self.request_service('ac2dm', 'com.google.android.gsf')

        logging.info('token: ' + self.token)

        _, self.auth = self.request_service('androidmarket', 'com.android.vending', MARKET_USER_AGENT)
        logging.info('auth: ' + self.auth)

        return self.auth is not None

    def details(self, package_name):
        """
        performs a GET request to get the details of a specific app
        :param package_name: the app to get details from
        :return: the details of the app
        """

        headers = {'X-DFE-Device-Id': self.android_id,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'User-Agent': MARKET_USER_AGENT}

        params = {'doc': package_name}
        response = self.session.get(GOOGLE_DETAILS_URL, params=params, headers=headers, allow_redirects=True)

        details_response = apkfetch_pb2.ResponseWrapper()
        details_response.ParseFromString(response.content)
        details = details_response.payload.detailsResponse.docV2
        if not details:
            raise Exception('Could not get details for: ' + package_name)
        if details_response.commands.displayErrorMessage != "":
            raise Exception(
                'error getting details: ' + details_response.commands.displayErrorMessage + " for: " + package_name)
        return details

    def reviews(self, package_name, amount=50):
        """
        performs a GET request to get the reviews of a specific app
        :param package_name: the app to get reviews from
        :param amount: amount of reviews to get
        :return: a list of reviews
        """

        headers = {'X-DFE-Device-Id': self.android_id,
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
            raise Exception('Could not get reviews for: ' + package_name)
        if review_response.commands.displayErrorMessage != "":
            raise Exception(
                'error getting reviews: ' + review_response.commands.displayErrorMessage + " for: " + package_name)
        return review_response.payload.reviewResponse.getResponse

    def get_download_url(self, package_name, version_code):
        """
        performs a GET request to get the download url of a specific app
        :param package_name: the app to get the download url from
        :param version_code: the version of the app to download
        :return: the download url
        """

        headers = {'X-DFE-Device-Id': self.android_id,
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
            raise Exception('Could not get download url for: ' + package_name)
        if delivery_response.commands.displayErrorMessage != "":
            raise Exception(
                'error getting download url: ' + delivery_response.commands.displayErrorMessage + " for: " + package_name)
        return delivery_response.payload.deliveryResponse.appDeliveryData.downloadUrl

    def purchase(self, package_name, version_code):
        """
        performs a GET request to get the download token of a specific app and complete the purchase
        :param package_name: the app to get the download token from
        :param version_code: the version of the app to get the download token from
        :return: return the download token
        """

        if version_code is None:
            raise Exception('no version code for purchase')

        headers = {
            "X-DFE-Encoded-Targets": "CAEScFfqlIEG6gUYogFWrAISK1WDAg+hAZoCDgIU1gYEOIACFkLMAeQBnASLATlASUuyAyqCAjY5igOMBQzfA/IClwFbApUC4ANbtgKVAS7OAX8YswHFBhgDwAOPAmGEBt4OfKkB5weSB5AFASkiN68akgMaxAMSAQEBA9kBO7UBFE1KVwIDBGs3go6BBgEBAgMECQgJAQIEAQMEAQMBBQEBBAUEFQYCBgUEAwMBDwIBAgOrARwBEwMEAg0mrwESfTEcAQEKG4EBMxghChMBDwYGASI3hAEODEwXCVh/EREZA4sBYwEdFAgIIwkQcGQRDzQ2fTC2AjfVAQIBAYoBGRg2FhYFBwEqNzACJShzFFblAo0CFxpFNBzaAd0DHjIRI4sBJZcBPdwBCQGhAUd2A7kBLBVPngEECHl0UEUMtQETigHMAgUFCc0BBUUlTywdHDgBiAJ+vgKhAU0uAcYCAWQ/5ALUAw1UwQHUBpIBCdQDhgL4AY4CBQICjARbGFBGWzA1CAEMOQH+BRAOCAZywAIDyQZ2MgM3BxsoAgUEBwcHFia3AgcGTBwHBYwBAlcBggFxSGgIrAEEBw4QEqUCASsWadsHCgUCBQMD7QICA3tXCUw7ugJZAwGyAUwpIwM5AwkDBQMJA5sBCw8BNxBVVBwVKhebARkBAwsQEAgEAhESAgQJEBCZATMdzgEBBwG8AQQYKSMUkAEDAwY/CTs4/wEaAUt1AwEDAQUBAgIEAwYEDx1dB2wGeBFgTQ",
            "User-Agent": MARKET_USER_AGENT,
            'X-DFE-Device-Id': self.android_id,
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
            raise Exception(
                'error performing purchase: ' + response.commands.displayErrorMessage + " for: " + package_name)
        else:
            download_token = response.payload.buyResponse.downloadToken
            return download_token

    def fetch(self, package_name, version_code, apk_fn=None):
        """
        download the app, by getting a download url.
        :param package_name: the app to download
        :param version_code: the version of the app to download
        :param apk_fn: predefined name, package_name by default
        :return: True if the download was successful, False otherwise.
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

    def get_related(self, browse_stream):
        """
        get the list of apps under the "more you might like" section under app details
        :param browse_stream: the link from the app details to request the list of related apps
        :return: a list of related apps and their details
        """

        headers = {'X-DFE-Device-Id': self.android_id,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'User-Agent': MARKET_USER_AGENT}

        response = self.session.get(GOOGLE_FDFE_URL + "/" + browse_stream, params=None, headers=headers,
                                    allow_redirects=True)

        related_response = apkfetch_pb2.ResponseWrapper()
        related_response.ParseFromString(response.content)

        if not related_response:
            raise Exception('Could not get related apps for')
        if related_response.commands.displayErrorMessage != "":
            raise Exception('error getting related apps: ' + related_response.commands.displayErrorMessage)
        return related_response.preFetch[0].response.payload.listResponse.doc[0]

    def get_category(self, url):
        """
        since the requests to the server do not return category information,
        this function gets the information from the website
        :param url: the apps url of the website version of the google play store
        :return: a list of categories
        """

        page = requests.get(url)
        tree = html.fromstring(page.content)
        category = tree.xpath('//a[@itemprop="genre"]/text()')
        return category

    def get_android_version(self, url):
        """
        since the requests to the server do not return android version information,
        this function gets the information from the website
        :param url: the apps url of the website version of the google play store
        :return: the minimum required android version string
        """

        page = requests.get(url)
        tree = html.fromstring(page.content)
        version = tree.xpath('//span[@class="htlgb"]/text()')
        return version[4]

    def load_visited_apps(self):
        """
        load all apps previously visited from the appinfo.csv file
        :return: a list of previously crawled apps
        """

        with open("apps"+os.sep+"data"+os.sep+"appinfo.csv", "r") as csvfile:
            file = csv.reader(csvfile, delimiter=',', quotechar='"')
            visited_apps = []

            for row in file:
                visited_apps += [row[0]]

            csvfile.close()

        # pop the column names
        visited_apps.pop(0)

        logging.info(
            str(len(visited_apps)) + " previously crawled apps loaded. This crawler won't crawl through these apps.")
        return visited_apps

    def store(self, details, reviews, related_apps):
        """
        store the details and reviews of an app into a .csv file
        :param details: the list of details of a specific app
        :param reviews: the list of reviews from a specific app
        :param related_apps: a list of related apps
        """

        with open("apps"+os.sep+"data"+os.sep+"appinfo.csv", "a") as csv_file:

            related_apps_string = ""
            for app in related_apps:
                related_apps_string += app.docid + ","
            related_apps_string = related_apps_string[:-1]

            url = "https://play.google.com/store/apps/details?id=" + details.docid + "&hl=en"

            category_string = ""
            for category in self.get_category(url):
                category_string += category + ","
            category_string = category_string[:-1]

            android_version = self.get_android_version(url)

            file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            file.writerow([details.docid, details.backendDocid, details.title, details.descriptionHtml,
                           details.descriptionShort,
                           url, "https://android.clients.google.com/fdfe/" + details.relatedLinks.youMightAlsoLike.url2,
                           related_apps_string, category_string, details.details.appDetails.appType,
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
                           details.details.appDetails.recentChangesHtml, android_version,
                           details.details.appDetails.installationSize, details.details.appDetails.unstable,
                           details.details.appDetails.hasInstantLink, details.details.appDetails.containsAds])
            csv_file.close()

        with open("apps"+os.sep+"data"+os.sep+"permissions.csv", "a") as csv_file:
            with open("templatePermissions.csv", "r") as permissionsFile:
                permissions = csv.reader(permissionsFile, delimiter=',', quotechar='"')
                file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                has_permission = [details.docid]
                for row in permissions:
                    if row[0] in details.details.appDetails.permission:
                        has_permission += [1]
                    else:
                        has_permission += [0]

                file.writerow(has_permission)
                permissionsFile.close()
            csv_file.close()

        with open("apps"+os.sep+"data"+os.sep+"externalpermissions.csv", "a") as csv_file:
            file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            external_permissions = [details.docid]
            for row in details.details.appDetails.permission:
                if not row.startswith("android.permission."):
                    external_permissions += [row]

            file.writerow(external_permissions)
            csv_file.close()

        with open("apps"+os.sep+"data"+os.sep+"images.csv", "a") as csv_file:
            file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            image_urls = [details.docid]
            for image in details.image:
                image_urls += [image.imageUrl]

            file.writerow(image_urls)
            csv_file.close()

        with open("apps"+os.sep+"data"+os.sep+"reviews.csv", "a") as csv_file:
            file = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

            for data in reviews.review:
                file.writerow([details.docid, data.documentVersion, data.timestampMsec, data.starRating, data.comment,
                               data.userProfile.personId, data.userProfile.name, data.userProfile.image[0].imageUrl])

            csv_file.close()

    def visit_app(self, package_name):
        """
        gets and stores the information and reviews of a specific package and downloads the apkfile
        :param package_name: the package to start from
        :return: a list of related apps to visit next
        """

        logging.info("started crawling through " + package_name + " on iteration: {}".format(self.iter))
        print("started crawling through " + package_name + " on iteration: {}".format(self.iter))
        details = self.details(package_name)
        version = details.details.appDetails.versionCode
        reviews = self.reviews(package_name, REVIEWS)

        if not DOWNLOAD_APPS:
            logging.info("downloading is turned off")
            time.sleep(5)
        elif details.offer[0].micros > 0:
            logging.warning("This app needs to be paid for in order to download")
        else:
            if self.purchase(package_name, version):
                logging.info("successful purchase")
            if self.fetch(package_name, version):
                logging.info('Downloaded version {}'.format(version))

        related_apps = self.get_related(details.relatedLinks.youMightAlsoLike.url2)

        if STORE_INFO:
            self.store(details, reviews, related_apps.child)

        return related_apps.child

    def crawl(self, package_name, visited_packages, max_iterations=1):
        """
        crawls through the google play store, provided with a starting package
        This is a recursive function. it crawls through the app, gets the information,
        the apk file and the related apps and moves on crawling through the related apps using recursion
        :param package_name: the package to start from
        :param visited_packages: a list of packages already visited
        :param max_iterations: the (max) amount of apps to crawl through
        """

        time.sleep(WAIT)
        self.iter += 1
        related_apps = []

        try:
            related_apps = self.visit_app(package_name)
        except Exception as e:
            print('Error:', str(e))

            if "Server busy" in str(e):  # in case of a timeout, we have to wait a while to be able to request again.
                logging.error('error: ' + str(e) + ".\n Server Timeout. Waiting 10 min and tying again. attempt 1 out of 5")
                time.sleep(600)
                for i in range(4):
                    try:
                        related_apps = self.visit_app(package_name)
                    except Exception as e:
                        print('Error:', str(e))
                        logging.critical(
                            'critical error: ' + str(e) + ".\n trying again. Waiting 10 min. attempt "+str(i+2)+" out of 5")
                        time.sleep(600)
                        if i == 3:
                            logging.info("moving on to the next app")
                            return

            else:  # in case of a response error, we wait a short while and try again.
                logging.error('error: ' + str(e) + ".\n Probably a server timeout. Waiting 60 sec and trying again.")
                time.sleep(60)

                try:
                    related_apps = self.visit_app(package_name)
                except Exception as e:
                    print('Error:', str(e))
                    logging.critical('critical error: ' + str(e) + ".\n Second try failed. Skipping this app and moving "
                                                                   "on to the next")
                    time.sleep(10)
                    return

        for app in related_apps:
            if app.docid not in visited_packages and self.iter < max_iterations:
                visited_packages += [app.docid]
                self.crawl(app.docid, visited_packages, max_iterations)


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
    parser.add_argument('--iterations', '-i', help='Amount of apps you want to crawl through', type=int)

    # prepare logging file
    logging.basicConfig(filename=datetime.now().strftime("logs"+os.sep+"%Y-%m-%d_%H-%M-%S.log"), level=logging.INFO,
                        format="%(asctime)s - %(levelname)s: %(message)s")

    # start timing the program
    start_time = time.time()

    try:
        # assign parsed values
        args = parser.parse_args(sys.argv[1:])

        user = args.user
        password = args.passwd
        android_id = args.androidid
        package = args.package
        max_iterations = args.iterations

        if not user or not password or not package or not android_id:
            parser.print_usage()
            raise ValueError('user, passwd, androidid and package are required options. android ID can be found using '
                             'Device id on your android device using an app from the playstore')

        # create class
        apk = GooglePlayCrawler()
        print("crawling through the playstore")

        # login
        apk.login(user, password, android_id)

        if not android_id and apk.android_id:
            print('AndroidID', apk.android_id)

        time.sleep(1)

    except Exception as e:
        print('authentication error:', str(e))
        logging.critical('authentication error:' + str(e) + ". terminating program")
        sys.exit(1)

    visited_apps = apk.load_visited_apps()
    if package not in visited_apps or not NO_DUPLICATE_DATA:
        logging.info("initiated crawling for " + str(max_iterations) + " apps")
        apk.crawl(package, visited_apps, max_iterations)
    else:
        print("package has been visited before. Pick a new package to start from or run resetcsvfiles.py to start over")
        logging.info(
            "package has been visited before. Pick a new package to start from or run resetcsvfiles.py to start over")

    print("finished crawling")
    print("crawled through {} apps in {:.1f} seconds".format(apk.iter, time.time() - start_time))
    logging.info("crawled through {} apps in {:.1f} seconds".format(apk.iter, time.time() - start_time))


if __name__ == "__main__":
    main(sys.argv[1:])
