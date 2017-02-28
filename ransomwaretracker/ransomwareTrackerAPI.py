"""
This is the (unofficial) Python API for http://ransomwaretracker.abuse.ch/tracker/ Website.

"""
from __future__ import print_function
from bs4 import BeautifulSoup
from enum import Enum

import requests
import sys
import json


class Threat(Enum):

    def __str__(self):
        return str(self.value)

    c2 = 'c2',
    payment_sites = 'payment-sites',
    distribution_sites = 'distribution-sites'

class Malware(Enum):

    def __str__(self):
        return str(self.value)

    TeslaCrypt = 'teslacrypt',
    CryptoWall = 'cryptowall', 
    TorrentLocker = 'torrentlocker',
    PadCrypt = 'padcrypt',
    Locky = 'locky',
    CTB_Locker = 'ctb-locker',
    FAKBEN = 'fakben',
    PayCrypt = 'paycrypt',
    DMALocker = 'dmalocker',
    Cerber = 'cerber'

class RansomwareTracker(object):

    """RansomwareTracker Main Handler"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)


    def extract_info_host(self, soup):
        res = {}
        res['host_information'] = {}
        table_host = soup.find('table', attrs={'class': 'tablehost'})
        for index, tr in enumerate(table_host.findAll('tr')):
            if index == 5:
                res['host_information']['blacklist_check'] = {}
                try:
                    res['host_information']['blacklist_check']['Spamhaus_DBL'] = tr.find('a')['href']
                except:
                    res['host_information']['blacklist_check']['Spamhaus_DBL'] = 'not_listed'
            elif index == 6:
                try:
                    res['host_information']['blacklist_check']['SURBL'] = tr.find('a')['href']
                except:
                    res['host_information']['blacklist_check']['SURBL'] = 'not_listed'
            else:
                res['host_information'][tr.find('th').text[:-1].replace(' ', '_')] = tr.find('td').text

        table_host = soup.find('table', attrs={'class': 'maintable'})
        res['results'] = []
        for tr in table_host.findAll('tr')[1:]:
            tds = tr.findAll('td')
            tmp_res = {
                'active': tds[0].text,
                'first_seen': tds[1].text,
                'last_seen': tds[2].text,
                'ip_address': tds[3].find('a').contents[0],
                'hostname': tds[4].text,
                'SBL': tds[5].text,
                'as_number': tds[6].text,
                'as_name': tds[7].text,
                'country': tds[8].text
            }
            res['results'].append(tmp_res)
        return res

    def host(self, host):
        # p27dokhpz2n7nvgr.15jznv.top
        url = 'http://ransomwaretracker.abuse.ch/host/{}/'.format(host)
        req = requests.get(url)

        soup = BeautifulSoup(req.content, 'html.parser')

        if req.status_code != 200:
            print(
                u"Unexpected status code from {url}: {code}".format(
                    url=sslbl_url, code=req.status_code),
                file=sys.stderr,
            )
            return []

        soup = BeautifulSoup(req.content, 'html.parser')
        return json.dumps(self.extract_info_host(soup))


    def extract_info_table(self, table):
        res = {}
        res['matches'] = []
        trs = table.findAll('tr')
        for tr in trs[1:]:
            tds = tr.findAll('td')
            data = {'date_added': tds[0].text, 
                    'threat': tds[1].text,
                    'malware': tds[2].text,
                    'host': tds[3].find('a').contents[0],
                    'domain_registrar':tds[4].text,
                    'ip_adress':tds[5].text}
            res['matches'].append(data)
        res['total'] = len(res['matches'])
        return res

    def retrieve_results(self, page=0, filter_with=None):
        sslbl_url = 'http://ransomwaretracker.abuse.ch/tracker/'

        if filter_with is not None:
            sslbl_url += filter_with[0]

        if page != 0:
            sslbl_url += '/page/{}'.format(page)

        req = requests.get(sslbl_url)
        soup = BeautifulSoup(req.content, 'html.parser')

        if req.status_code != 200:
            print(
                u"Unexpected status code from {url}: {code}".format(
                    url=sslbl_url, code=req.status_code),
                file=sys.stderr,
            )
            return []

        soup = BeautifulSoup(req.content, 'html.parser')
        table = soup.findAll('table', attrs={'class': 'maintable'})[0]
        return json.dumps(self.extract_info_table(table))

