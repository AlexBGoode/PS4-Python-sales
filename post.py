#! /usr/bin/python
# -*- coding: utf-8 -*-

# opkg install git
# opkg install git-http
# git clone https://github.com/AlexBGoode/PS4-Python-sales.git
# will create a folder "always" containing this script

# easy_install simplejson
# easy_install gspread
# easy_install oauth2client
# cat ps4sales-aef32dacd287.json | ssh asus "cat > /..../ps4sales-aef32dacd287.json"
# cat data.json | ssh asus "cat > /..../data.json"
## asus # opkg install ca-certificates -> Segmentation fault
## easy_install-2.7 --user urllib3 ???
## easy_install-2.7 --user ndg_httpsclient ??? error: [Errno 12] Cannot allocate memory
## easy_install pyOpenSSL ??? error: [Errno 12] Cannot allocate memory
## '/Library/Python/2.7/site-packages/httplib2-0.9.2-py2.7.egg/httplib2/cacerts.txt'
# asus # unzip /tmp/mnt/sda1/entware/lib/python2.7/site-packages/httplib2-0.9.2-py2.7.egg # !!! works



import sys, os, logging
from datetime import datetime
import time
import requests
import simplejson
import re
from HTMLParser import HTMLParser
import gspread
from oauth2client.client import GoogleCredentials
from logging.handlers import TimedRotatingFileHandler
logger = logging.getLogger(__name__)

os.environ['TZ'] = 'Europe/Moscow'
time.tzset()

# import urllib3.contrib.pyopenssl
# urllib3.contrib.pyopenssl.inject_into_urllib3()
# # easy_install-2.7 --user urllib3
# # easy_install-2.7 --user ndg_httpsclient




class GoogleTables():


    def __init__(self, table_key="1cbDYsZ0TESPJRtnJzwA78oLn6WDhgcAXOB8PjCKeNos"):
        self.path = os.path.dirname(os.path.realpath(__file__))
        self.key = table_key
        # json_key = simplejson.load(open('ps4sales-aef32dacd287.json'))
        scope = ['https://spreadsheets.google.com/feeds']
        credentials = GoogleCredentials.from_stream(self.path + '/ps4sales-aef32dacd287.json').create_scoped(scope)
        gc = gspread.authorize(credentials)
        self.wks = gc.open_by_key(self.key)   # psn accounts
        return

    def getWorksheet(self, name):
        return self.wks.worksheet(name)


class Sales():
    def __init__(self):
        self.path = os.path.dirname(os.path.realpath(__file__))

        logger.setLevel(logging.DEBUG)
        logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
        consoleHandler = logging.StreamHandler(sys.stdout)
        consoleHandler.setFormatter(logFormatter)
        consoleHandler.setLevel(logging.INFO)
        logger.addHandler(consoleHandler)
        # Adding the rotation log message handler
        logFilename = self.path + "/log.txt"
        fileHandler = TimedRotatingFileHandler(logFilename, when='h', backupCount=3)
        fileHandler.setFormatter(logFormatter)
        fileHandler.setLevel(logging.DEBUG)
        logger.addHandler(fileHandler)

        self.host = "gafuk.ru"
        self.port = 80
        self.s = requests.Session()
        self.s.headers.update({'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) ' +
                                             'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                                             'Chrome/48.0.2564.116 Safari/537.36'})
        self.html_parser = HTMLParser()
        self.server_url = "http://%s:%s" % (self.host, self.port)
        self.workbook = GoogleTables()
        return

    def loadConfig(self, configName):
        # self.login = None
        # password = None
        filename = self.path + "/" + configName + ".json"
        # print "Loading the data file:\n" + filename
        with open(filename) as data_file:
            data = simplejson.load(data_file)
        return data

    def saveConfig(self, configName, data):
        filename = self.path + "/" + configName + ".json"
        # print "Writing data to the file:\n" + filename
        with open(filename, 'w') as f:
            c_json = simplejson.dumps(data)
            f.write(c_json)
        return

    def login(self, login, password):
        url=self.server_url + "/login"
        try:
            data = self.loadConfig('cookies')
            # print data
            c = requests.utils.cookiejar_from_dict(data)
            self.s.cookies = c
        except StandardError as e:
            logger.debug("No cookies found %s" % (e.message))


        r = self.s.get(url)
        html = r.text
        regex = re.compile('class="my_profile ">[\s]+<a href="\/users\/(?P<user>\w+)"')
        # ckecking if the link to the user profile is in place
        m = regex.search(html)
        if m != None:
            logger.info('Good, already logged in as ' + m.group('user'))
        else:
            # looking for a credential prompt (with csrf_token)
            token = self.parse_csrf_token(html)
            if len(token) == 0:
                logger.error("Problem with logging in\n" + html)

            # found the prompt for credentials, so need to extract csrf_token...
            data={"login": login, "pass": password, "csrf_token": token[0]}
            logger.debug("Going for a fresh login with csrf_token " + token[0])

            # ...and then login
            r = self.s.post(url, data=data)
            html = r.text
            # ckecking if the link to the user profile is in place
            m = regex.search(html)
            if m != None:
                logger.info('Logged in as ' + m.group('user'))
            else:
                msg = 'Unsuccessful login for user ' + login
                logger.error(msg + '\n' + html)
                raise StandardError(msg)

            # allright, save session cookies for next time
            c_dict = requests.utils.dict_from_cookiejar(self.s.cookies)
            self.saveConfig('cookies', c_dict)

        return self.s


    def parse_csrf_token(self, html):
        regex = re.compile('<input +type *= *"hidden" +name *= *"csrf_token" +value *= *"(.*)" */>')
        token = regex.findall(html)
        return token



    def list_my_posts(self, login, forums = None, page = None):
        page=1
        url=self.server_url + "/forum/" + login + "_activity.html?page=" + str(page)
        # r = requests.get(url, data=params, cookies=cookies)
        r = self.s.get(url)
        html = r.text
        # parsing HTML for posts only in sales forums
        re_str = '<div class="post-td date"><a href="' +\
                 '(?P<URL>/forum/thread(?P<forumID>88|96).+)">#.+div.*div>' +\
                 '(?P<timestamp>.+)</div>'
        result = []
        for m in re.finditer(re_str, html):
            result.append(m.groupdict())

        return result

    def post_adv_message(self, forumID, message):
        msg = ' successful posting to the forum '
        html = None
        # pre-requesting to get csrf_token
        url=self.server_url + '/forum/reply' + forumID + '.html'
        r = self.s.get(url)
        try:
            html = r.text
            token = self.parse_csrf_token(html)
            # get IndexError in case of site restrictions to post
            data={"csrf_token": token[0], "gosend": 1, "message": message}
            # print url, data
            logger.debug("Request to publish the adv: %s %s"
                         % (url, simplejson.dumps(data, ensure_ascii=False)))
            r = self.s.post(url, data)
            html = r.text
            # we'd better chech the response for errors
            # looking for the avatar area of the post with a back reference to the profile,
            # means presence of the post
            re_str = 'class="my_profile ">\s*<a href="(?P<user>\/users\/\w+)"[\W\w]+' + \
                     '<a name="(?P<postID>\d+)" ' + \
                     'href="(?P<postURL>\/forum\/thread(?P<forumID>\d+)-?\d+.html#(?P=postID))">' + \
                     '#\w+<\/a>[\w\W]+ class="post-td avatar"><a href="(?P=user)"'
            # logger.debug(re_str)
            m = re.search(re_str, html)
            if m != None:
                logger.debug('Confirmed' + msg + simplejson.dumps(m.groupdict()))
                return m.groupdict()    # return key info in the posted message
            else:
                raise IndexError(msg)
        except IndexError as e:
            msg = 'No' + msg + forumID
            logger.error(msg + '\n' + html)
            raise StandardError(msg)



    def delete_by_url(self, post_url):
        url=self.server_url + post_url
        # pre-requesting to get csrf_token and others parameters needed
        r = self.s.get(url)
        html = r.text
        try:
            # if the link is found then it could be deleted
            m = re.search('onclick="forum.deletePost\(' +
                          '(?P<postID>\d+), \'(?P<csrf_token>\w+)\', (?P<pageID>\d+)\);">',
                          html)
            # first hit should be good enouth
            # url=self.server_url + "/forum/deletepost" + keys[0] + ".html"
            url = "%s/forum/deletepost%s.html" % (self.server_url, m.group('postID'))
            data={"csrf_token": m.group('csrf_token'), "page": m.group('pageID')}
            logger.debug("Request to delete the post: %s %s" % (url, data))
            # now perform the deletion
            r = self.s.post(url,data)
            # print r.text # {"error":false,"redirect":"\/forum\/thread96-3.html"}
            resp_json = simplejson.loads(r.text)
            if resp_json['error'] != False:
                raise StandardError("Delete error: " +
                                    simplejson.dumps([data, resp_json], ensure_ascii=False))

        except AttributeError:  # if re.search returns None
            # no link - no deletion
            logger.debug("It's undeletable")
            return

    def get_adv_for_forum(self, forumID):
        msg = 'No advertisement to post in the forum: '
        salesWS = self.workbook.getWorksheet("sale")

        if "96" == forumID:   # unofficial
            advs = salesWS.range("H5:H6")
        elif "88" == forumID: # official
            advs = salesWS.range("G5:G6")
        else:
            raise ReferenceError(msg + forumID)

        message = advs[1].value    # column F
        # if title == '-':
        if len(message) < 10:   # short message means nothing to sell
            raise ReferenceError(msg + forumID) # to be caught at end of sales loop
        else:
            title = advs[0].value    # column F
            logger.info ('Got an account to sell: ' + title)
            logger.debug('Got a message to publish: ' + message)
            return {"title": title, "message": message}

    def unescape(self, html_string):
        return self.html_parser.unescape(html_string)

    def checkAllAccounts(self):
        status = None
        accWS = self.workbook.getWorksheet('accounts')

        # the account counter = number of lines with a PSN login
        cnt = int(accWS.acell('F2').value)
        logger.debug("PSN accounts to check: %i" % (cnt))
        res = dict()
        res['accounts_total'] = cnt
        res['to_sell'] = res['errors'] = 0
        line = 3    # starting from a row 3

        # increase line number and decrease the account counter
        while True:
            # line_str = str(line)
            range = "E%s:H%s" % (line, line)
            account_row = accWS.range(range)
            psn_login = account_row[1].value    # column F
            # if the whole line isn't empty...
            if psn_login:   # ...isn't empty
                cnt -= 1    # if a PSN account is found then less remain

                psn_password = account_row[2].value     # column G
                title = account_row[0].value            # column E
                # is_actual = len(psn_password)>0
                # if is_actual:
                if psn_password:    # isn't empty
                    result = self.check_psn_game(psn_login, psn_password)
                    if result['error'] is False:
                        status = 'Ok'   # update status in A column
                        # report the last activated device name in L column
                        last_device = result['last_device']
                        accWS.update_cell(line, 12, last_device)
                        # indicate ability to deactivate in K column
                        deactivatable = result['can_deactivate']
                        accWS.update_cell(line, 11, deactivatable)
                        if deactivatable:
                            res['to_sell'] = res['to_sell'] + 1
                        # logger.info("[Line %s] Account [Ok]: %s (%s), deactivatable: %s, activated at: %s"
                        #             % (line, psn_login, title, deactivatable, last_device))
                        logger.info("[Line %s] Account [Ok]: %s (%s), %s @ %s"
                                    % (line, psn_login, title,
                                       "deactivatable" if deactivatable else '---', last_device))
                    else:
                        status = '!'    # update status in A column
                        logger.error("[Line %s] %s (%s)" % (line, result['message'], title))
                        res['errors'] = res['errors'] + 1

                    # logger.info("[Line %s] Is to check my account: %s (%s)" % (line, psn_login, title))
                    accWS.update_cell(line, 1, status) # update status in A column for any line
                else:
                    # Do nothing for sold accounts
                    status = '' # reset status in A column
                    logger.debug("[Line %s]\tAccount sold: %s (%s)" % (line, psn_login, title))


            else:
                # Do nothing for empty lines
                status = ''     # reset status in A column

            accWS.update_cell(line, 1, status) # update status in A column

            timestamp = datetime.strftime(datetime.now(), '%d.%m.%Y %H:%M')
            accWS.update_cell(line, 2, timestamp) # record timestamp

            logger.debug("Lines processed: %s, accounts remain: %s" % (line, cnt))
            if cnt == 0:    # loop untill the account couneter > 0
                break # and return

            line += 1

        res['lines_processed'] = line
        return res

    def check_psn_game(self, psn_login, psn_password):
        try:
            base = 'https://account.sonyentertainmentnetwork.com'
            # logging out for consistency
            url = base + '/liquid/j_spring_security_logout'
            r = self.s.get(url)
            html = r.text
            self.s = requests.Session()
            # need to get struts token
            # regex = re.compile('<input type="hidden" name="struts.token" value="(.*)" />')
            # token = str(regex.findall(html)[0])
            # print token

            # logging in and also checking the last activated device
            # url = base + '/liquid/j_spring_security_check'
            url = base + '/liquid/j_spring_security_check'
            data={"j_username": psn_login, "j_password": psn_password,
                  # "struts.token.name": "struts.token", "struts.token": token,
                  "service-entity": "np"}
            r = self.s.post(url, data)
            # r = requests.post(url, data=data)
            # r = self.s.get(url)
            html = r.text
            # checking if logged in
            regex = re.compile('<span id="currentUsernameSpan">(.*)</span>')
            token = regex.findall(html)
            if len(token) == 0:
                # logger.info(html)
                logger.debug(html)
                raise StandardError('No successful login with ' + psn_login)
            # parsing for the last activated device
            regex = re.compile('<div class="lastDeviceName">(.*)</div>')
            token = regex.findall(html)
            if len(token) > 0:
                last_device = self.unescape(token[0])
            else:
                last_device = None
            logger.debug("Last activated device: %s" % (last_device))

            can_deactivate = False
            if last_device is not None:
                # now going another page to check the activation
                url = base + '/liquid/cam/devices/device-media-list.action'
                r = self.s.get(url)
                html = r.text
                # parsing for the deactivation button
                regex = re.compile('gameMessageButtonWrapper"(?: class="gameMessageButtonWrapperClass")?>\s+' +
                                   '(?P<deactivatable><section id="gamedeactivateAllButtonWrapper)?')
                act = regex.search(html)
                if act is None:
                    logger.debug(html)
                    raise StandardError('No activation info retrieved')
                else:
                    if act.group('deactivatable') is not None:
                        can_deactivate = True
                    else:
                        can_deactivate = False

                logger.debug("Deactivation button: %s" % (can_deactivate))

            return {"error": False, "last_device": last_device, "can_deactivate": can_deactivate}
        except StandardError as err:
            return {"error": True, "message": err.message}

    def get_adv_and_post(self, forumID):
        adv = self.get_adv_for_forum(forumID)
        time.sleep(30)
        # msg = adv['message']
        # logger.debug("Got the message to publish:\n" + msg)
        self.post_adv_message(forumID, adv['message'])
        time.sleep(30)
        # logger.debug(post)
        return adv['title']


    def doSale(self):
        # Logging in only here
        data = self.loadConfig('data')
        login=data['user']
        password=data['password']
        # host=data['host']
        self.login(login, password)

        # self.test()

        forums = {"96":None, "88":None}

        # Print all my existing advertisements
        my_posts = self.list_my_posts(login)
        # logger.debug("My posted advertisements: " +
        #              simplejson.dumps(my_posts, ensure_ascii=False, indent=3))

        # Iterate thru both sales forums
        for forumID in forums:
            logger.info("Processing the sales forum " + forumID)

            try:
                for post in my_posts:
                    # post = my_posts[k]
                    pURL = post['URL']
                    # pForumID = post['forumID']
                    pTime = post['timestamp']
                    # 0=URL, 1-forum-id, 2=time
                    if forumID == post['forumID']:
                        logger.info("My advertisement found: " + pURL)

                        # delete only if dated yesterday and later, if 'today' not found
                        if pTime.find(u'сегодня') == -1:
                            # try to delete it
                            self.delete_by_url(pURL)
                            title = self.get_adv_and_post(forumID)
                            # Report the succesful deletion and posting by the forum object
                            forums[forumID] = 'Reposted successfully: ' + title
                            # Jumping out to process the next forum
                            raise ReferenceError(forums[forumID])
                        else:
                            # Report the refusal by the corresponding forum object
                            forums[forumID] = 'No repost possible, dated: ' + pTime
                            # Jumping out to process the next forum
                            raise ReferenceError(forums[forumID])

                title = self.get_adv_and_post(forumID)
                # Report the succesful posting by the corresponding forum object
                forums[forumID] = 'Posted successfully: ' + title
                logger.info(forums[forumID])
            except ReferenceError as e:
                forums[forumID] = e.message
                logger.info(e.message)
        return forums

    def test(self):
        r = self.s.get('http://gafuk.ru/forum/thread96-3.html#182331')
        # r = self.s.get('http://gafuk.ru/forum/thread96-4.html')
        html = r.text
        # logger.debug(html)
        # looking for the avatar area of the post with a back reference to the profile,
        # means presence of the post
        # re_str = 'class="my_profile ">\s*<a href="(\/users\/\w+)"[\W\w]+' +\
        #          '<a name="(\d+)" href="(\/forum\/thread(\d+)-?\d+.html#\2)">#\w+<\/a>[\w\W]+' +\
        #          'class="post-td avatar"><a href="\1"'
        re_str = ''.join((
                'class="my_profile ">\s*<a href="(?P<user>\/u.+\/\w+)"[\W\w]+', # link to the user profile
                '<a n.+="(?P<postID>\d+)"\s',                                   # link to the desired post
                'href="(?P<postURL>\/f.+\/t.+(?P<forumID>\d+)-?\d+.html#(?P=postID))">#\w+<\/a>',
                '[\w\W]+c.+="post-td avatar"><a href="(?P=user)"'))             # back reference to profile
        # logger.debug(re_str)
        m = re.search(re_str, html)
        msg = ' successful posting to the forum '
        if m is not None:
            logger.info(m.groupdict ())
            logger.info('Confirmed' + msg)
        else:
            msg = 'No' + msg
            logger.error(msg)
            logger.debug(html)
            raise StandardError(msg)



        print 1/0


if __name__ == '__main__':


    ps4 = Sales()
    saleResults = checkResults = None
    checkResults = ps4.checkAllAccounts()
    # saleResults = ps4.doSale()
    # print salesResult
    logger.info('\n' + simplejson.dumps(
                {'sales': saleResults, 'control': checkResults},
                ensure_ascii=False,
                indent=3))
