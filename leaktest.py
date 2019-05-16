#!/usr/bin/env python3
# Selenium Proxy Tester via ipleak.net
# Darkerego, March 2019 ~ xelectron@protonmail.com

"""
This program checks for dns/webrtc, and other ip leaks using https://ipleak.net. It is intended to
help developers properly integrate proxies with their selenium powered applications. HTTP/HTTPS proxy
support tested with proxybroker(https://github.com/constverum/ProxyBroker). Did this program help you?
Tips are always appreciated .... BTC:1DQrNswQdr4tk9KURNfUcyENk6gQXT7Nyj and I am currently for hire (xelectron@protonmail.com)
"""

from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options
from colorama import init, Fore
import argparse
import json
import getpass
import stem.connection
import stem.socket

init(autoreset=True)


def printlog(data, outfile):
    """

    :param data: log and print this to stdout
    :param outfile: to fhis file
    :return: -
    """
    pp_json(data)
    with open(outfile, 'a') as log:
        log.write(str(data) + "\n")


def cycle_ident(tor_pass):
    """

    :param tor_pass: password to auth with tor for identity rotation
    :return:
    """
    """

    :param tor_pass: password to authenticate to tor control port
    :return: -- exit upon failure
    """

    try:
        control_socket = stem.socket.ControlPort(port=9051)
    except stem.SocketError as exc:
        print('Unable to connect to port 9051 (%s)' % exc)
        return False

    try:
        stem.connection.authenticate(control_socket)
    except stem.connection.IncorrectSocketType:
        print('Please check in your torrc that 9051 is the ControlPort.')
        print('Maybe you configured it to be the ORPort or SocksPort instead?')
        return False
    except stem.connection.MissingPassword:
        if not tor_pass:
            controller_password = getpass.getpass('Controller password: ')
        else:
            controller_password = tor_pass

        try:
            stem.connection.authenticate_password(control_socket, controller_password)
        except stem.connection.PasswordAuthFailed:
            print('Unable to authenticate, password is incorrect')
            return False
    except stem.connection.AuthenticationFailure as exc:
        print('Unable to authenticate: %s' % exc)
        return False


def pp_json(json_thing, sort=True, indents=4):
    if type(json_thing) is str:
        print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
    else:
        print(json.dumps(json_thing, sort_keys=sort, indent=indents))
    return None


def check_ip(version, debug, proxy, tor_proxy, outfile):
    """

    :param version: ipv4 or ipv6
    :param debug: don't use headless mode (for debugging)
    :param proxy: use this proxy server
    :param tor_proxy: configure browser for tor proxy
    :param outfile: log to this file
    :return: --
    """
    opts = Options()
    if not debug:
        opts.set_headless()
        assert opts.headless  # Operating in headless mode

    profile = webdriver.FirefoxProfile()
    # set FF preference to socks proxy
    if proxy:
        print('Setting proxy...')
        proxy = proxy.split(':')
        proxy_host = proxy[0]
        proxy_port = proxy[1]
        proxy_port = int(proxy_port)
        profile.set_preference("network.proxy.type", 1)
        if not tor_proxy:
            profile.set_preference("network.proxy.http", proxy_host)
            profile.set_preference("network.proxy.http_port", proxy_port)
            profile.set_preference('network.proxy.https', proxy_host)
            profile.set_preference('network.proxy.https', proxy_port)
            profile.set_preference('network.proxy.ssl', proxy_host)
            profile.set_preference('network.proxy.ssl_port', proxy_port)
        else:
            profile.set_preference("network.proxy.socks", proxy_host)
            profile.set_preference("network.proxy.socks_port", proxy_port)
            profile.set_preference("network.proxy.socks_version", 5)
        profile.set_preference('network.proxy_dns', 'true')

    profile.update_preferences()
    browser = Firefox(options=opts, firefox_profile=profile)
    if version == 4:
        get_url = 'https://ipv4.ipleak.net/json/'
    else:
        get_url = 'https://ipv6.ipleak.net/json/'
    try:
        browser.get(get_url)
    except Exception as selenium_err:
        print(Fore.RED + 'Error getting data: ')
        print(selenium_err)
    else:

        data = json.loads(browser.find_element_by_tag_name('body').text)
        if outfile:
            printlog(data, outfile)
        else:
            pp_json(data)
    finally:
        browser.close()


def main():
    """ Program Start
    :return: --
    """

    usage = "usage: %[prog] <-4/-6> - Skeletal selenium ip leak checker."
    usage += "\nRecommended: Use proxybroker with types HTTP, HTTPS, and SOCKS5"
    usage += "\n.%[%PROG]With proxybroker: %prog -p localhost:8888"
    usage += "\n./[%prog]With tor and control pass; -t -p localhost:9050 -c 'controllerpassword'"
    parser = argparse.ArgumentParser(usage)
    parser.add_argument('-4', '--ip_v4', default=False, help='Do ipv4 test: (default) ',
                        dest='ip_version4', action='store_true')
    parser.add_argument('-6', '--ip_v6', default=False, help='Do ipV6 test ',
                        dest='ip_version6', action='store_true')
    #
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help='Run in non-headless '
                                                                                 'mode for debugging.')
    parser.add_argument('-p', '--proxy', dest='proxy', default=None, help='Use an HTTP/HTTPS proxy such as proxybroker.'
                                                                          'Example: localhost:8888')
    parser.add_argument('-t', '--tor_proxy', action='store_true', dest='tor_proxy', default=False,
                        help='Use tor proxy (at localhost:9050 if not set).Enables automatic identity cycling '
                             'via control port at localhost:9150')
    parser.add_argument('-c', '--control_password', dest='tor_pass', help='Password to authenticate tor control port.')
    parser.add_argument('-o', '--outfile', dest='outfile', default='proxytest.log', help='Log to this file.')

    number_list = []
    args = parser.parse_args()

    if args.ip_version4 and args.ip_version6:
        print('Either use -4 o -6 , not both!')
        exit(1)
    if args.ip_version4:
        version = 4
    elif args.ip_version6:
        version = 6
    else:
        version = 4
    outfile = args.outfile

    if args.tor_proxy:
        print('Using tor proxy. Will automatically request a new identity after each query. Ensure control'
              'port is enabled (localhost:9150) , setting proxy to localhost:9050, override with --proxy')
        proxy = '127.0.0.1:9050'
        tor_proxy = args.tor_proxy
    else:
        tor_proxy = False
    if args.proxy is not None:
        proxy = args.proxy
    if args.tor_pass:
        tor_pass = args.tor_pass
    else:
        tor_pass = None

    debug = args.debug

    print(Fore.GREEN + 'Running ipv%d test ... ' % version)
    try:
        check_ip(version, debug, proxy, tor_proxy, outfile)
    except Exception as err:
        print(Fore.RED + 'Error:' + str(err))
    else:
        print(Fore.BLUE + 'Success!')

    if tor_proxy:
        print(Fore.BLUE + 'Cycling tor identity ...')
        try:
            cycle_ident(tor_pass)
        except:
            print('Error cycling tor identity')


if __name__ == '__main__':
    main()
