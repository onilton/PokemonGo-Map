#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
 - Captcha Overseer:
   - Tracks incoming new captcha tokens
   - Monitors the captcha'd accounts queue
   - Launches captcha_solver threads
 - Captcha Solver Threads each:
   - Have a unique captcha token
   - Attempts to verifyChallenge
   - Puts account back in active queue
   - Pushes webhook messages with captcha status
'''

import logging
import math
import os
import sys
import traceback
import random
import time
import requests
import copy

from datetime import datetime, timedelta
from threading import Thread, Lock
from queue import Queue, Empty
from sets import Set

from pgoapi import PGoApi
from .fakePogoApi import FakePogoApi

from .models import Token
from .transform import jitter_location
from .account import check_login
from .proxy import get_new_proxy

log = logging.getLogger(__name__)

def captcha_overseer_thread(args, account_queue, captcha_queue):
    solverId = 0
    captchaStatus = {}

    while True:
        # Run once every 15 seconds.
        sleep_timer = 15

        tokens_needed = captcha_queue.qsize()
        if tokens_needed > 0:
            tokens = Token.get_valid(tokens_needed)
            tokens_available = len(tokens)
            solvers = min(tokens_needed, tokens_available)
            log.info('Accounts on hold with captcha: %d - tokens available: %d',
                     tokens_needed, tokens_available)
            for i in range(0, solvers):
                captcha = captcha_queue.get()
                captchaStatus[solverId] = {
                    'type': 'Solver',
                    'message': 'Creating captcha solving thread...',
                    'account': captcha['account'],
                    'location': captcha['last_step'],
                    'captcha_url': captcha['captcha_url'],
                    'token':  tokens[i]
                }

                t = Thread(target=captcha_solving_thread,
                           name='captcha-solver-{}'.format(solverId),
                           args=(args, account_queue, captcha_queue,
                                 captchaStatus[solverId]))
                t.daemon = True
                t.start()

                captcha_queue.task_done()
                solverId += 1
                if solverId > 999:
                    solverId = 0
                # Wait a bit before launching next captcha-solver thread
                time.sleep(1)

            # Adjust captcha-overseer sleep timer
            sleep_timer -= 1 * solvers
        log.debug("Waiting %d seconds before next token query...", sleep_timer)
        time.sleep(sleep_timer)


def captcha_solving_thread(args, account_queue, captcha_queue, status):

    account = status['account']
    location = status['location']
    captcha_url = status['captcha_url']
    captcha_token = status['token']

    status['message'] = 'Waking up account {} to verify captcha token.'.format(
                         account['username'])
    log.info(status['message'])

    if args.mock != '':
        api = FakePogoApi(args.mock)
    else:
        api = PGoApi()

    proxy_url = False
    if args.proxy:
        # Try to fetch a new proxy
        proxy_num, proxy_url = get_new_proxy(args)

        if proxy_url:
            log.debug("Using proxy %s", proxy_url)
            api.set_proxy({'http': proxy_url, 'https': proxy_url})

    # Jitter location up to 100 meters
    location = jitter_location(location, 100)
    api.set_position(*location)
    status['message'] = 'Logging in...'
    check_login(args, account, api, location, proxy_url)

    response = api.verify_challenge(token=captcha_token)

    if 'success' in response['responses']['VERIFY_CHALLENGE']:
        status['message'] = "Account {} successfully uncaptcha'd, returning to active duty.".format(account['username'])
        log.info(status['message'])
        account_queue.put(account)
    else:
        status['message'] = 'Account {} failed verifyChallenge, putting back in captcha queue.'.format(account['username'])
        log.warning(status['message'])
        captcha_queue.put({'account': account, 'last_step': location, 'captcha_url': captcha_url})

def token_request(args, status, url):
    s = requests.Session()
    # Fetch the CAPTCHA_ID from 2captcha.
    try:
        request_url = (
            "http://2captcha.com/in.php?key={}&method=userrecaptcha" +
            "&googlekey={}&pageurl={}").format(args.captcha_key,
                                               args.captcha_dsk, url)
        captcha_id = s.post(request_url).text.split('|')[1]
        captcha_id = str(captcha_id)
    # IndexError implies that the retuned response was a 2captcha error.
    except IndexError:
        return 'ERROR'
    status['message'] = (
        'Retrieved captcha ID: {}; now retrieving token.').format(captcha_id)
    log.info(status['message'])
    # Get the response, retry every 5 seconds if it's not ready.
    recaptcha_response = s.get(
        "http://2captcha.com/res.php?key={}&action=get&id={}".format(
            args.captcha_key, captcha_id)).text
    while 'CAPCHA_NOT_READY' in recaptcha_response:
        log.info("Captcha token is not ready, retrying in 5 seconds...")
        time.sleep(5)
        recaptcha_response = s.get(
            "http://2captcha.com/res.php?key={}&action=get&id={}".format(
                args.captcha_key, captcha_id)).text
    token = str(recaptcha_response.split('|')[1])
    return token


def calc_distance(pos1, pos2):
    R = 6378.1  # KM radius of the earth.

    dLat = math.radians(pos1[0] - pos2[0])
    dLon = math.radians(pos1[1] - pos2[1])

    a = math.sin(dLat / 2) * math.sin(dLat / 2) + \
        math.cos(math.radians(pos1[0])) * math.cos(math.radians(pos2[0])) * \
        math.sin(dLon / 2) * math.sin(dLon / 2)

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    d = R * c

    return d


# Delay each thread start time so that logins occur after delay.
def stagger_thread(args):
    loginDelayLock.acquire()
    delay = args.login_delay + ((random.random() - .5) / 2)
    log.debug('Delaying thread startup for %.2f seconds', delay)
    time.sleep(delay)
    loginDelayLock.release()


# The delta from last stat to current stat
def stat_delta(current_status, last_status, stat_name):
    return current_status.get(stat_name, 0) - last_status.get(stat_name, 0)


class TooManyLoginAttempts(Exception):
    pass
