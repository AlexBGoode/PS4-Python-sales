import simplejson, os
import json
import requests
import urllib

class Auth:

    oauth = None
    last_error = None
    npsso = None
    grant_code = None
    refresh_token = None

    SSO_URL = 'https://auth.api.sonyentertainmentnetwork.com/2.0/ssocookie'
    CODE_URL = 'https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize'
    OAUTH_URL = 'https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token'

    scope_string =  "capone:report_submission,psn:sceapp,user:account.get,user:account.settings.privacy.get," \
                    "user:account.settings.privacy.update,user:account.realName.get,user:account.realName.update," \
                    "kamaji:get_account_hash,kamaji:ugc:distributor,oauth:manage_device_usercodes"

    duid_string =   "0000000d000400808F4B3AA3301B4945B2E3636E38C0DDFC"

    login_request = {
                        "authentication_type": 'password',
                        "username": None,
                        'password': None,
                        'client_id': '71a7beb8-f21a-47d9-a604-2e71bee24fe0'
    }

    oauth_request = {
                        "app_context": "inapp_ios",
                        "client_id": "b7cbf451-6bb6-4a5a-8913-71e61f462787",
                        "client_secret": "zsISsjmCx85zgCJg",
                        "code": None,
                        "duid": duid_string,
                        "grant_type": "authorization_code",
                        "scope": scope_string
    }

    code_request = {
                        "state": "06d7AuZpOmJAwYYOWmVU63OMY",
                        "duid": duid_string,
                        "app_context": "inapp_ios",
                        "client_id": "b7cbf451-6bb6-4a5a-8913-71e61f462787",
                        "scope": scope_string,
                        "response_type": "code"
                    }

    refresh_oauth_request = {
                        "app_context": "inapp_ios",
                        "client_id": "b7cbf451-6bb6-4a5a-8913-71e61f462787",
                        "client_secret": "zsISsjmCx85zgCJg",
                        "refresh_token": None,
                        "duid": duid_string,
                        "grant_type": "refresh_token",
                        "scope": scope_string
    }

    two_factor_auth_request = {
                        "authentication_type": "two_step",
                        "ticket_uuid": None,
                        "code": None,
                        "client_id": "b7cbf451-6bb6-4a5a-8913-71e61f462787",
    }

    def __init__(self, email, password, ticket='', code=''):
        self.session = requests.Session()
        # self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) ' +
        #                                      'AppleWebKit/537.36 (KHTML, like Gecko) ' +
        #                                      'Chrome/48.0.2564.116 Safari/537.36'})
        self.session.headers.update({'User-Agent': 'PlayStationApp/3.20.2 (iPhone; iOS 9.2.1; Scale/2.00)'})
        self.login_request['username'] = email
        self.login_request['password'] = password
        self.two_factor_auth_request['ticket_uuid'] = ticket
        self.two_factor_auth_request['code'] = code
        self.GrabNPSSO()
        ## if (self.GrabNPSSO() is False or self.GrabCode() is False or self.GrabOAuth() is False):
        ##     print('Error')


    def GrabNPSSO(self):
        if self.two_factor_auth_request['ticket_uuid'] and self.two_factor_auth_request['code']:
            data = urllib.parse.urlencode(self.two_factor_auth_request).encode('utf-8')
            request = urllib.request.Request(self.SSO_URL, data = data)
            response = urllib.request.urlopen(request)
            data = json.loads(response.read().decode('utf-8'))
        else:
            response = self.session.post(self.SSO_URL, json=self.login_request)
            data = simplejson.loads(response.text)
            if hasattr(data, 'error'):
                return False
            if hasattr(data, 'ticket_uuid'):
                error = {
                    'error': '2fa_code_required',
                    'error_description': '2FA Code Required',
                    'ticket': data['ticket_uuid']
                }
                self.last_error = json.dumps(error)
                return False
            self.npsso = data['npsso']
            return True

    def GrabLoginCookies(self):
        cookies = dict(npsso=self.npsso)
        response = self.session.get(self.CODE_URL, params=self.code_request, cookies=cookies)
        return self.session.cookies

