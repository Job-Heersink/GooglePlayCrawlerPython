from __future__ import print_function

import os
import sys
import time
import argparse
import requests
import csv

import apkfetch_pb2

from util import encrypt

DOWNLOAD_FOLDER_PATH = 'apps/'

GOOGLE_LOGIN_URL = 'https://android.clients.google.com/auth'
GOOGLE_CHECKIN_URL = 'https://android.clients.google.com/checkin'
GOOGLE_DETAILS_URL = 'https://android.clients.google.com/fdfe/details'
GOOGLE_DELIVERY_URL = 'https://android.clients.google.com/fdfe/delivery'
GOOGLE_PURCHASE_URL = 'https://android.clients.google.com/fdfe/purchase'
GOOGLE_BROWSE_URL = 'https://android.clients.google.com/fdfe/browse'
GOOGLE_LIST_URL = 'https://android.clients.google.com/fdfe/list'

LOGIN_USER_AGENT = 'GoogleLoginService/1.3 (gts3llte)'
MARKET_USER_AGENT = 'Android-Finsky/5.7.10 (api=3,versionCode=80371000,sdk=24,device=falcon_umts,hardware=qcom,product=falcon_reteu,platformVersionRelease=4.4.4,model=XT1032,buildId=KXB21.14-L1.40,isWideScreen=0)'
CHECKIN_USER_AGENT = 'Android-Checkin/2.0 (gts3llte)'
DOWNLOAD_USER_AGENT = 'AndroidDownloadManager/9 (Linux; U; Android 9; XT1032 Build/KXB21.14-L1.40)'
DEVICE = {
    "name": "[my samsung A70]",
    "UserReadableName": "Samsung Galaxy Tab S3 (api24)",  #
    "Build.HARDWARE": "qcom",  #
    "Build.RADIO": "T825XXU1AQK3",  #
    "Build.BOOTLOADER": "T825XXU1ARA2",  #
    "Build.FINGERPRINT": "samsung/a70qeea/a70q:9/PpR1.180610.011/A705FNXXU3ASI2:user/release-keys",
    "Build.BRAND": "samsung",  #
    "Build.DEVICE": "gts3llte",  #
    "Build.VERSION.SDK_INT": 24,  #
    "Build.MODEL": "SM-A705FN",
    "Build.MANUFACTURER": "samsung",
    "Build.PRODUCT": "a70qeea",
    "Build.ID": "NRD90M",  #
    "Build.VERSION.RELEASE": 7.0,  #
    "TouchScreen": 3,  #
    "Keyboard": 1,  #
    "Navigation": 1,  #
    "ScreenLayout": 4,  #
    "HasHardKeyboard": False,  #
    "HasFiveWayNavigation": False,  #
    "GL.Version": 196610,  #
    "Screen.Density": 320,  #
    "Screen.Width": 1536,  #
    "Screen.Height": 2048,  #
    "Platforms": "arm64-v8a,armeabi-v7a,armeabi",  #
    "SharedLibraries": "SemAudioThumbnail,SmpsManager,allshare,android.ext.services,android.ext.shared,android.test.runner,com.android.future.usb.accessory,com.android.location.provider,com.android.media.remotedisplay,com.android.mediadrm.signer,com.dsi.ant.antradio_library,com.google.android.gms,com.google.android.maps,com.google.android.media.effects,com.qti.ims.connectionmanager.imscmlibrary,com.qti.location.sdk,com.qti.snapdragon.sdk.display,com.qti.vzw.ims.internal,com.quicinc.wbc,com.quicinc.wbcservice,com.samsung.android.knox.knoxsdk,com.samsung.bbc,com.samsung.device,com.sec.android.app.minimode,com.sec.android.app.multiwindow,com.sec.android.mdm,com.sec.android.mdm.gearpolicymanager,com.sec.android.visualeffect,com.sec.dcm,com.sec.esecomm,com.sec.smartcard.auth,com.suntek.mway.rcs.client.aidl,com.suntek.mway.rcs.client.api,imsmanager,izat.xt.srv,javax.obex,libvtmanagerjar,org.apache.http.legacy,org.simalliance.openmobileapi,saiv,scamera_sdk_util,scrollpause,sec_feature,sec_platform_library,seccamera,sechardware,secimaging,seclvbmanager,secmediarecorder,secvision,semcamera,semextendedformat,simageis,smatlib,stayrotation,sws,touchwiz,videoeditor_sdk",
    "Features": "android.hardware.audio.output,android.hardware.bluetooth,android.hardware.bluetooth_le,android.hardware.camera,android.hardware.camera.any,android.hardware.camera.autofocus,android.hardware.camera.capability.manual_post_processing,android.hardware.camera.capability.manual_sensor,android.hardware.camera.capability.raw,android.hardware.camera.flash,android.hardware.camera.front,android.hardware.camera.level.full,android.hardware.faketouch,android.hardware.fingerprint,android.hardware.location,android.hardware.location.gps,android.hardware.location.network,android.hardware.microphone,android.hardware.opengles.aep,android.hardware.screen.landscape,android.hardware.screen.portrait,android.hardware.sensor.accelerometer,android.hardware.sensor.compass,android.hardware.sensor.gyroscope,android.hardware.sensor.light,android.hardware.sensor.stepcounter,android.hardware.sensor.stepdetector,android.hardware.telephony,android.hardware.telephony.gsm,android.hardware.touchscreen,android.hardware.touchscreen.multitouch,android.hardware.touchscreen.multitouch.distinct,android.hardware.touchscreen.multitouch.jazzhand,android.hardware.usb.accessory,android.hardware.usb.host,android.hardware.vulkan.level,android.hardware.vulkan.version,android.hardware.wifi,android.hardware.wifi.direct,android.software.app_widgets,android.software.backup,android.software.connectionservice,android.software.device_admin,android.software.freeform_window_management,android.software.home_screen,android.software.input_methods,android.software.live_wallpaper,android.software.managed_users,android.software.midi,android.software.print,android.software.sip,android.software.sip.voip,android.software.verified_boot,android.software.voice_recognizers,android.software.vr.mode,android.software.webview,com.samsung.android.api.version.2402,com.samsung.android.authfw,com.samsung.android.knox.knoxsdk,com.samsung.android.sdk.camera.processor,com.samsung.android.sdk.camera.processor.dof,com.samsung.android.sdk.camera.processor.effect,com.samsung.android.sdk.camera.processor.gif,com.samsung.android.sdk.camera.processor.haze,com.samsung.android.sdk.camera.processor.hdr,com.samsung.android.sdk.camera.processor.lls,com.samsung.android.sdk.camera.processor.panorama,com.samsung.feature.device_category_tablet,com.samsung.feature.hdr_capable,com.samsung.feature.samsung_experience_mobile,com.samsung.feature.virtualscreen,com.sec.android.mdm,com.sec.android.secimaging,com.sec.android.smartface.smart_stay,com.sec.feature.barcode_emulator,com.sec.feature.cover,com.sec.feature.cover.flip,com.sec.feature.findo,com.sec.feature.fingerprint_manager_service,com.sec.feature.hovering_ui,com.sec.feature.motionrecognition_service,com.sec.feature.nsflp,com.sec.feature.overlaymagnifier,com.sec.feature.sensorhub,com.sec.feature.slocation,com.sec.feature.spen_usp",
    "Locales": "ar,ar_AE,ar_IL,as,as_IN,ast,az,az_AZ,be,be_BY,bg,bg_BG,bn,bn_BD,bn_IN,bs,bs_BA,ca,ca_ES,cs,cs_CZ,da,da_DK,de,de_AT,de_CH,de_DE,el,el_GR,en,en_AU,en_CA,en_GB,en_IE,en_NZ,en_PH,en_US,en_ZA,en_ZG,es,es_ES,es_US,et,et_EE,eu,eu_ES,fa,fa_IR,fi,fi_FI,fil,fil_PH,fr,fr_BE,fr_CA,fr_CH,fr_FR,ga,ga_IE,gl,gl_ES,gu,gu_IN,hi,hi_IN,hr,hr_HR,hu,hu_HU,hy,hy_AM,in,in_ID,is,is_IS,it,it_IT,iw,iw_IL,ja,ja_JP,ka,ka_GE,kk,kk_KZ,km,km_KH,kn,kn_IN,ko,ko_KR,ky,ky_KG,lo,lo_LA,lt,lt_LT,lv,lv_LV,mk,mk_MK,ml,ml_IN,mn,mn_MN,mr,mr_IN,ms,ms_MY,my,my_MM,my_ZG,nb,nb_NO,ne,ne_NP,nl,nl_BE,nl_NL,or,or_IN,pa,pa_IN,pl,pl_PL,pl_SP,pt,pt_BR,pt_PT,ro,ro_RO,ru,ru_RU,si,si_LK,sk,sk_SK,sl,sl_SI,sq,sq_AL,sr,sr_Latn,sr_RS,sv,sv_SE,ta,ta_IN,te,te_IN,tg,tg_TJ,th,th_TH,tk,tk_TM,tr,tr_TR,uk,uk_UA,ur,ur_PK,uz,uz_UZ,vi,vi_VN,zh,zh_CN,zh_HK,zh_TW",
    "GSF.version": 12521022,  #
    "Vending.version": 80951000,  #
    "Vending.versionString": "9.5.10-all [0] [PR] 192200278",  #
    "CellOperator": "26203",  #
    "SimOperator": "Youfone",  #
    "Roaming": "mobile-notroaming",  #
    "Client": "android-google",  #
    "TimeZone": "Europe/Berlin",  #
    "GL.Extensions": "GL_AMD_compressed_ATC_texture,GL_AMD_performance_monitor,GL_ANDROID_extension_pack_es31a,GL_APPLE_texture_2D_limited_npot,GL_ARB_vertex_buffer_object,GL_ARM_shader_framebuffer_fetch_depth_stencil,GL_EXT_YUV_target,GL_EXT_blit_framebuffer_params,GL_EXT_buffer_storage,GL_EXT_clip_cull_distance,GL_EXT_color_buffer_float,GL_EXT_color_buffer_half_float,GL_EXT_copy_image,GL_EXT_debug_label,GL_EXT_debug_marker,GL_EXT_discard_framebuffer,GL_EXT_disjoint_timer_query,GL_EXT_draw_buffers_indexed,GL_EXT_geometry_shader,GL_EXT_gpu_shader5,GL_EXT_multisampled_render_to_texture,GL_EXT_primitive_bounding_box,GL_EXT_protected_textures,GL_EXT_robustness,GL_EXT_sRGB,GL_EXT_sRGB_write_control,GL_EXT_shader_framebuffer_fetch,GL_EXT_shader_io_blocks,GL_EXT_shader_non_constant_global_initializers,GL_EXT_tessellation_shader,GL_EXT_texture_border_clamp,GL_EXT_texture_buffer,GL_EXT_texture_cube_map_array,GL_EXT_texture_filter_anisotropic,GL_EXT_texture_format_BGRA8888,GL_EXT_texture_norm16,GL_EXT_texture_sRGB_R8,GL_EXT_texture_sRGB_decode,GL_EXT_texture_type_2_10_10_10_REV,GL_KHR_blend_equation_advanced,GL_KHR_blend_equation_advanced_coherent,GL_KHR_debug,GL_KHR_no_error,GL_KHR_texture_compression_astc_hdr,GL_KHR_texture_compression_astc_ldr,GL_OES_EGL_image,GL_OES_EGL_image_external,GL_OES_EGL_image_external_essl3,GL_OES_EGL_sync,GL_OES_blend_equation_separate,GL_OES_blend_func_separate,GL_OES_blend_subtract,GL_OES_compressed_ETC1_RGB8_texture,GL_OES_compressed_paletted_texture,GL_OES_depth24,GL_OES_depth_texture,GL_OES_depth_texture_cube_map,GL_OES_draw_texture,GL_OES_element_index_uint,GL_OES_framebuffer_object,GL_OES_get_program_binary,GL_OES_matrix_palette,GL_OES_packed_depth_stencil,GL_OES_point_size_array,GL_OES_point_sprite,GL_OES_read_format,GL_OES_rgb8_rgba8,GL_OES_sample_shading,GL_OES_sample_variables,GL_OES_shader_image_atomic,GL_OES_shader_multisample_interpolation,GL_OES_standard_derivatives,GL_OES_stencil_wrap,GL_OES_surfaceless_context,GL_OES_texture_3D,GL_OES_texture_compression_astc,GL_OES_texture_cube_map,GL_OES_texture_env_crossbar,GL_OES_texture_float,GL_OES_texture_float_linear,GL_OES_texture_half_float,GL_OES_texture_half_float_linear,GL_OES_texture_mirrored_repeat,GL_OES_texture_npot,GL_OES_texture_stencil8,GL_OES_texture_storage_multisample_2d_array,GL_OES_vertex_array_object,GL_OES_vertex_half_float,GL_OVR_multiview,GL_OVR_multiview2,GL_OVR_multiview_multisampled_render_to_texture,GL_QCOM_alpha_test,GL_QCOM_extended_get,GL_QCOM_tiled_rendering"
}


def num_to_hex(num):
    hex_str = format(num, 'x')
    length = len(hex_str)
    return hex_str.zfill(length + length % 2)


class APKfetch(object):

    def __init__(self):
        self.session = requests.Session()
        self.user = self.passwd = self.androidid = self.token = self.auth = None

    def request_service(self, service, app, user_agent=LOGIN_USER_AGENT):
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
        # print(response.text)
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

    def checkin(self):
        headers = {'User-Agent': CHECKIN_USER_AGENT,
                   'Content-Type': 'application/x-protobuf'}

        cr = apkfetch_pb2.AndroidCheckinRequest()

        cr.id = 0
        cr.marketCheckin = self.user
        cr.accountCookie.append(self.auth[5:])
        cr.deviceConfiguration.touchScreen = DEVICE["TouchScreen"]
        cr.deviceConfiguration.keyboard = DEVICE["Keyboard"]
        cr.deviceConfiguration.navigation = DEVICE["Navigation"]
        cr.deviceConfiguration.screenLayout = DEVICE["ScreenLayout"]
        cr.deviceConfiguration.hasHardKeyboard = DEVICE["HasHardKeyboard"]
        cr.deviceConfiguration.hasFiveWayNavigation = DEVICE["HasFiveWayNavigation"]
        cr.deviceConfiguration.screenDensity = DEVICE["Screen.Density"]
        cr.deviceConfiguration.screenWidth = DEVICE["Screen.Width"]
        cr.deviceConfiguration.screenHeight = DEVICE["Screen.Height"]
        cr.deviceConfiguration.glEsVersion = DEVICE["GSF.version"]

        libList = DEVICE["SharedLibraries"].split(",")
        featureList = DEVICE["Features"].split(",")
        localeList = DEVICE["Locales"].split(",")
        glList = DEVICE["GL.Extensions"].split(",")
        platforms = DEVICE["Platforms"].split(",")

        for x in platforms:
            cr.deviceConfiguration.nativePlatform.append(x)
        for x in libList:
            cr.deviceConfiguration.systemSharedLibrary.append(x)
        for x in featureList:
            cr.deviceConfiguration.systemAvailableFeature.append(x)
        for x in localeList:
            cr.deviceConfiguration.systemSupportedLocale.append(x)
        for x in glList:
            cr.deviceConfiguration.glExtension.append(x)
        cr.version = 3
        cr.fragment = 0

        cr.checkin.build.id = DEVICE["Build.FINGERPRINT"]
        cr.checkin.build.product = DEVICE["Build.HARDWARE"]
        cr.checkin.build.carrier = DEVICE["Build.BRAND"]
        cr.checkin.build.radio = DEVICE["Build.RADIO"]
        cr.checkin.build.bootloader = DEVICE["Build.BOOTLOADER"]
        cr.checkin.build.device = DEVICE["Build.DEVICE"]
        cr.checkin.build.sdkVersion = DEVICE["Build.VERSION.SDK_INT"]
        cr.checkin.build.model = DEVICE["Build.MODEL"]
        cr.checkin.build.manufacturer = DEVICE["Build.MANUFACTURER"]
        cr.checkin.build.buildProduct = DEVICE["Build.PRODUCT"]
        cr.checkin.build.client = DEVICE["Client"]
        cr.checkin.build.otaInstalled = False
        cr.checkin.build.timestamp = int(time.time())
        cr.checkin.build.googleServices = DEVICE["GSF.version"]
        cr.checkin.lastCheckinMsec = 0
        cr.checkin.cellOperator = DEVICE["CellOperator"]
        cr.checkin.simOperator = DEVICE["SimOperator"]
        cr.checkin.roaming = DEVICE["Roaming"]
        cr.checkin.userNumber = 0

        response = self.session.post(GOOGLE_CHECKIN_URL, data=cr.SerializeToString(), headers=headers,
                                     allow_redirects=True)

        checkin_response = apkfetch_pb2.AndroidCheckinResponse()
        checkin_response.ParseFromString(response.content)
        token = num_to_hex(checkin_response.securityToken)
        androidid = num_to_hex(checkin_response.androidId)
        return token, androidid

    def login(self, user, passwd, androidid=None):
        self.user = user
        self.passwd = passwd
        self.androidid = androidid

        self.token, self.auth = self.request_service('ac2dm', 'com.google.android.gsf')

        print('token: ', self.token)

        if not androidid:
            _, self.androidid = self.checkin()

        _, self.auth = self.request_service('androidmarket', 'com.android.vending', MARKET_USER_AGENT)
        print('auth: ', self.auth)

        return self.auth is not None

    def details(self, package_name):
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
        print(details_response.payload.detailsResponse.docV2)
        details = details_response.payload.detailsResponse.docV2
        if not details:
            raise RuntimeError('Could not get details')
        return details

    def get_download_url(self, package_name, version_code):
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

        url = delivery_response.payload.deliveryResponse.appDeliveryData.downloadUrl
        return url

    def purchase(self, packageName, versionCode, expansion_files=False):

        if versionCode is None:
            raise RuntimeError('no version code for purchase')

        headers = {'X-DFE-Device-Id': self.androidid,
                   'X-DFE-Client-Id': 'am-android-google',
                   'Accept-Encoding': '',
                   'Host': 'android.clients.google.com',
                   'Authorization': 'GoogleLogin Auth=' + self.auth,
                   'Content-Typ': 'application/x-www-form-urlencoded; charset=UTF-8'}

        useragent = ("Android-Finsky/{versionString} ("
                     "api=3"
                     ",versionCode={versionCode}"
                     ",sdk={sdk}"
                     ",device={device}"
                     ",hardware={hardware}"
                     ",product={product}"
                     ",platformVersionRelease={platform_v}"
                     ",model={model}"
                     ",buildId={build_id}"
                     ",isWideScreen=0"
                     ",supportedAbis={supported_abis}"
                     ")").format(versionString=DEVICE["Vending.versionString"],
                                 versionCode=DEVICE["Vending.version"],
                                 sdk=DEVICE["Build.VERSION.SDK_INT"],
                                 device=DEVICE["Build.DEVICE"],
                                 hardware=DEVICE["Build.HARDWARE"],
                                 product=DEVICE["Build.PRODUCT"],
                                 platform_v=DEVICE["Build.VERSION.RELEASE"],
                                 model=DEVICE["Build.MODEL"],
                                 build_id=DEVICE["Build.ID"],
                                 supported_abis=DEVICE["Platforms"].replace(',', ';'))
        headers = {
            "X-DFE-Encoded-Targets": "CAEScFfqlIEG6gUYogFWrAISK1WDAg+hAZoCDgIU1gYEOIACFkLMAeQBnASLATlASUuyAyqCAjY5igOMBQzfA/IClwFbApUC4ANbtgKVAS7OAX8YswHFBhgDwAOPAmGEBt4OfKkB5weSB5AFASkiN68akgMaxAMSAQEBA9kBO7UBFE1KVwIDBGs3go6BBgEBAgMECQgJAQIEAQMEAQMBBQEBBAUEFQYCBgUEAwMBDwIBAgOrARwBEwMEAg0mrwESfTEcAQEKG4EBMxghChMBDwYGASI3hAEODEwXCVh/EREZA4sBYwEdFAgIIwkQcGQRDzQ2fTC2AjfVAQIBAYoBGRg2FhYFBwEqNzACJShzFFblAo0CFxpFNBzaAd0DHjIRI4sBJZcBPdwBCQGhAUd2A7kBLBVPngEECHl0UEUMtQETigHMAgUFCc0BBUUlTywdHDgBiAJ+vgKhAU0uAcYCAWQ/5ALUAw1UwQHUBpIBCdQDhgL4AY4CBQICjARbGFBGWzA1CAEMOQH+BRAOCAZywAIDyQZ2MgM3BxsoAgUEBwcHFia3AgcGTBwHBYwBAlcBggFxSGgIrAEEBw4QEqUCASsWadsHCgUCBQMD7QICA3tXCUw7ugJZAwGyAUwpIwM5AwkDBQMJA5sBCw8BNxBVVBwVKhebARkBAwsQEAgEAhESAgQJEBCZATMdzgEBBwG8AQQYKSMUkAEDAwY/CTs4/wEaAUt1AwEDAQUBAgIEAwYEDx1dB2wGeBFgTQ",
            "User-Agent": useragent,
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
                  'doc': packageName,
                  'vc': versionCode}

        response = requests.post(GOOGLE_PURCHASE_URL, headers=headers,
                                 params=params, verify=True,
                                 timeout=60)

        response = apkfetch_pb2.ResponseWrapper.FromString(response.content)
        if response.commands.displayErrorMessage != "":
            raise RuntimeError('error performing purchase: ' + response.commands.displayErrorMessage)
        else:
            downloadtoken = response.payload.buyResponse.downloadToken
            return downloadtoken

    def fetch(self, package_name, version_code, apk_fn=None):
        url = self.get_download_url(package_name, version_code)
        if not url:
            raise RuntimeError('Could not get download URL')

        response = self.session.get(url, headers={'User-Agent': DOWNLOAD_USER_AGENT},
                                    stream=True, allow_redirects=True)

        print("downloading...")
        apk_fn = apk_fn or (DOWNLOAD_FOLDER_PATH + package_name + '/' + package_name + '.apk')
        if os.path.exists(apk_fn):
            os.remove(apk_fn)

        with open(apk_fn, 'wb') as fp:
            for chunk in response.iter_content(chunk_size=5 * 1024):
                if chunk:
                    fp.write(chunk)
                    fp.flush()
            fp.close()

        return os.path.exists(apk_fn)

    def store(self, details):
        with open(DOWNLOAD_FOLDER_PATH + details.docid + "/userdescription.csv", "w") as csvfile:
            file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            # TODO implement the rest from detailsURL
            # TODO fix uninteded commas in messages
            file.writerow(['Pkgname', details.docid])
            file.writerow(['backendPkgname', details.backendDocid])
            file.writerow(['Title', details.title])
            file.writerow(['Description', '"{}"'.format(details.descriptionHtml)])
            file.writerow(['Url', "!"])
            file.writerow(['Genre', "!"])
            # TODO implement category info
            file.writerow(['Type', details.details.appDetails.appType])
            # TODO fix this
            # file.writerow(['Price', details.offer.micros/1000000, details.offer.currencyCode])

            file.writerow(['Downloads', details.details.appDetails.numDownloads])
            file.writerow(['Rating', details.relatedLinks.rated.label])
            file.writerow(['StarRating', details.aggregateRating.starRating])
            file.writerow(['RatingCount', details.aggregateRating.ratingsCount])
            file.writerow(['ReviewsAverage', "!"])
            file.writerow(['FiveStarRatings', details.aggregateRating.fiveStarRatings])
            file.writerow(['FourStarRatings', details.aggregateRating.fourStarRatings])
            file.writerow(['ThreeStarRatings', details.aggregateRating.threeStarRatings])
            file.writerow(['TwoStarRatings', details.aggregateRating.twoStarRatings])
            file.writerow(['OneStarRatings', details.aggregateRating.oneStarRatings])

            file.writerow(['DeveloperAddress', "!"])
            file.writerow(['DeveloperEmail', details.details.appDetails.developerEmail])
            file.writerow(['DeveloperWebsite', details.details.appDetails.developerWebsite])
            file.writerow(['developerName', details.details.appDetails.developerName])
            file.writerow(['Creator', details.creator])

            file.writerow(['PrivacyPolicyLink', details.relatedLinks.privacyPolicyUrl])
            # TODO: youMightAlsoLike can be implemented, related links etc

            file.writerow(['CurrentVersion', details.details.appDetails.versionCode])
            file.writerow(['CurrentVersionString', details.details.appDetails.versionString])
            file.writerow(['LastUpdated', details.details.appDetails.uploadDate])
            file.writerow(['recentChanges', '"{}"'.format(details.details.appDetails.recentChangesHtml)])
            file.writerow(['AndroidVersion', "!"])

            file.writerow(['FileSize', details.details.appDetails.installationSize])
            file.writerow(['isUnstable', details.details.appDetails.unstable])
            file.writerow(['hasInstantLink', details.details.appDetails.hasInstantLink])
            file.writerow(['containsAds', details.details.appDetails.containsAds])
            csvfile.close()

        with open(DOWNLOAD_FOLDER_PATH + details.docid + "/permissions.csv", "w") as csvfile:
            with open("templatePermissions.csv", "r") as permissionsFile:
                permissions = csv.reader(permissionsFile, delimiter=',', quotechar='"')
                file = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                for row in permissions:
                    if row[0] in details.details.appDetails.permission:
                        file.writerow([row[0], 1])
                    else:
                        file.writerow([row[0], 0])

                # TODO now it just secretly adds unknown fields
                for row in details.details.appDetails.permission:
                    if not row.startswith("android.permission."):
                        file.writerow([row, 1])

                permissionsFile.close()
            csvfile.close()

        with open(DOWNLOAD_FOLDER_PATH + details.docid + "/technical.csv", "w") as csvfile:
            csvfile.close()

        with open(DOWNLOAD_FOLDER_PATH + details.docid + "/images.csv", "w") as csvfile:
            csvfile.close()

        with open(DOWNLOAD_FOLDER_PATH + details.docid + "/dependensies.csv", "w") as csvfile:
            csvfile.close()


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
    parser.add_argument('--search', '-s', help='Find all versions of the app that are available', action='store_true')

    try:
        # assign parsed values
        args = parser.parse_args(sys.argv[1:])

        user = args.user
        passwd = args.passwd
        androidid = args.androidid
        package = args.package
        version = args.version

        if not user or not passwd or not package:
            parser.print_usage()
            raise ValueError('user, passwd, and package are required options')

        # create class
        apk = APKfetch()

        # login
        apk.login(user, passwd, androidid)

        if not androidid and apk.androidid:
            print('AndroidID', apk.androidid)

        details = apk.details(package)
        version = version or details.details.appDetails.versionCode

        if not os.path.exists(DOWNLOAD_FOLDER_PATH + package):
            os.mkdir(DOWNLOAD_FOLDER_PATH + package)

        apk.store(details)

        # TODO maybe you can browse by putting the related in link front of android.user.google

        if apk.purchase(package, version):
            print("successful purchase")
        if apk.fetch(package, version):
            print('Downloaded version', version)

    except Exception as e:
        print('Error:', str(e))
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
