#!/usr/bin/env python3
# Selenium Proxy Tester via ipleak.net
# Darkerego, March 2019 ~ xelectron@protonmail.com

print("""
#  ╔═╗┌─┐┬##┌─┐┌┐┌┬┬#┬┌┬┐╔═╗┬─┐┌─┐─┐#┬┬#┬╔╦╗┌─┐┌─┐┌┬┐
#  ╚═╗├┤#│##├┤#│││││#││││╠═╝├┬┘│#│┌┴┬┘└┬┘#║#├┤#└─┐#│#
#  ╚═╝└─┘┴─┘└─┘┘└┘┴└─┘┴#┴╩##┴└─└─┘┴#└─#┴##╩#└─┘└─┘#┴#
""")

"""This program checks for dns/webrtc, and other ip leaks using https://ipleak.net. It is intended to
help developers properly integrate proxies with their selenium powered applications. SOCKS/HTTP/HTTPS proxy
support tested with proxybroker(https://github.com/constverum/ProxyBroker), tor, and ssh. Did this program help you?
Tips are always appreciated .... BTC:1DQrNswQdr4tk9KURNfUcyENk6gQXT7Nyj
I am currently for hire (xelectron@protonmail.com)
"""
import time
from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options
from colorama import init, Fore
import argparse
import json
import getpass
import stem.connection
import stem.socket
# global variables
init(autoreset=True)
global quiet_mode


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
        _print('Unable to connect to port 9051 (%s)' % exc)
        return False

    try:
        stem.connection.authenticate(control_socket)
    except stem.connection.IncorrectSocketType:
        _print('Please check in your torrc that 9051 is the ControlPort.')
        _print('Maybe you configured it to be the ORPort or SocksPort instead?')
        return False
    except stem.connection.MissingPassword:
        if not tor_pass:
            controller_password = getpass.getpass('Controller password: ')
        else:
            controller_password = tor_pass

        try:
            stem.connection.authenticate_password(control_socket, controller_password)
        except stem.connection.PasswordAuthFailed:
            _print('Unable to authenticate, password is incorrect')
            return False
    except stem.connection.AuthenticationFailure as exc:
        _print('Unable to authenticate: %s' % exc)
        return False


def pp_json(json_thing, sort=True, indents=4):
    if type(json_thing) is str:
        print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
    else:
        print(json.dumps(json_thing, sort_keys=sort, indent=indents))
    return None


def check_ip(version, debug, proxy, tor_proxy, proxy_type, outfile):
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
    if not proxy:
        proxy = None
    # set FF preference to socks proxy
    if proxy or tor_proxy:
        _print('Setting proxy...')
        if proxy is not None:
            proxy = proxy.split(':')
            proxy_host = str(proxy[0])
            proxy_port = int(proxy[1])
            _print('Proxy: %s:%d' % (proxy_host, proxy_port))
            profile.set_preference("network.proxy.type", 1)
            if tor_proxy or proxy_type == 'tor':
                profile.set_preference("network.proxy.socks", proxy_host)
                profile.set_preference("network.proxy.socks_port", proxy_port)
                profile.set_preference("network.proxy.socks_version", 5)
                profile.set_preference('network.proxy_dns', 'true')  # Proxy DNS
            elif proxy_type == 'socks5':
                profile.set_preference("network.proxy.socks", proxy_host)
                profile.set_preference("network.proxy.socks_port", proxy_port)
                profile.set_preference("network.proxy.socks_version", 5)
                profile.set_preference('network.proxy_dns', 'true')  # Proxy DNS
            elif proxy_type == 'socks4':
                profile.set_preference("network.proxy.socks", proxy_host)
                profile.set_preference("network.proxy.socks_port", proxy_port)
                profile.set_preference("network.proxy.socks_version", 4)
            elif proxy_type == 'http':
                profile.set_preference("network.proxy.http", proxy_host)
                profile.set_preference("network.proxy.http_port", proxy_port)
                profile.set_preference('network.proxy.https', proxy_host)
                profile.set_preference('network.proxy.https', proxy_port)
                profile.set_preference('network.proxy.ssl', proxy_host)
                profile.set_preference('network.proxy.ssl_port', proxy_port)
                profile.set_preference('network.proxy_dns', 'true')  # Proxy DNS

    profile.update_preferences()
    browser = Firefox(options=opts, firefox_profile=profile)
    if version == 4:
        get_url = 'https://ipv4.ipleak.net/json/'
    else:
        get_url = 'https://ipv6.ipleak.net/json/'
    try:
        browser.get(get_url)
    except Exception as selenium_err:
        _print(Fore.RED + 'Error getting data: ')
        _print(selenium_err)
        if debug:
            print('Closing browser in 60 seconds...')
            time.sleep(60)
            browser.close()
        return False
    else:
        data = json.loads(browser.find_element_by_tag_name('body').text)
        if outfile:
            printlog(data, outfile)
        else:
            pp_json(data)
    finally:
        browser.close()


def _print(data: object) -> object:
    """
    override builtin print function if quiet mode is specified
    :param data: print this data (or don't)
    :return: --
    """
    if quiet_mode:
        pass
    else:
        print(data)

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
    parser.add_argument('-p', '--proxy', dest='proxy', default=None,
                        help='Use a SOCKS/HTTP/HTTPS proxy such as proxybroker, ssh or likewise. '
                             'Example: localhost:1080')
    parser.add_argument('-T', '--proxy_type', choices='[socks4, socks5, http, tor ]', default='socks5',
                        dest='proxy_type', help='Proxy type to test. Default: socks5. For HTTPS support, just specify HTTP.')
    parser.add_argument('-t', '--tor_proxy', action='store_true', dest='tor_proxy', default=False,
                        help='Use tor proxy (at localhost:9050 if not set).Enables automatic identity cycling '
                             'via control port at localhost:9150')
    parser.add_argument('-c', '--control_password', dest='tor_pass', help='Password to authenticate tor control port.')
    parser.add_argument('-n', '--new_identity', dest='cycle', action='store_true', default=False,
                        help='Do not attempt to cycle tor identity.')
    parser.add_argument('-o', '--outfile', dest='outfile', default='proxytest.log', help='Log to this file.')
    parser.add_argument('-q', '--quiet', dest='quiet', default=False, action='store_true', help='Only output json, '
                                                                                                'do not output '
                                                                                                'console messages.')

    args = parser.parse_args()
    global quiet_mode
    cycle = args.cycle
    quiet_mode = args.quiet

    if args.ip_version4 and args.ip_version6:
        print(Fore.RED + 'Either use -4 o -6 , not both!')
        exit(1)
    if args.ip_version4:
        version = 4
    elif args.ip_version6:
        version = 6
    else:
        version = 4
    outfile = args.outfile
    proxy_type = args.proxy_type
    if args.proxy:
        proxy = args.proxy

    else:
        _print(Fore.RED + "This program is intended to check the reliability of a proxy -- "
                          "Running with a direct connection because no proxy specified ... ")
        proxy = None
    if args.tor_proxy:
        _print('Using tor proxy. Will automatically request a new identity after each query. Ensure control '
               'port is enabled (localhost:9150) , setting proxy to localhost:9050, override with --proxy')
        if args.proxy is None:
            proxy = '127.0.0.1:9050'
        tor_proxy = args.tor_proxy
    else:
        tor_proxy = False

    if args.tor_pass:
        tor_pass = args.tor_pass
    else:
        tor_pass = None

    debug = args.debug

    _print(Fore.GREEN + 'Running ipv%d test ... ' % version)
    # Main Logic Here
    try:
        ret = check_ip(version, debug, proxy, tor_proxy, proxy_type, outfile)
    except Exception as err:
        if quiet_mode:
            err = str(err)
            print(json.dumps({"Error": "%s"}) % err)
        else:
            _print(Fore.RED + "Error checking IP: " + str(err))
    else:
        if ret:
            _print(Fore.BLUE + 'Success!')

    if tor_proxy and cycle:
        _print(Fore.BLUE + 'Cycling tor identity ...')
        try:
            cycle_ident(tor_pass)
        except Exception as err:
            _print('Error cycling tor identity: ' + str(err))


if __name__ == '__main__':
    main()
