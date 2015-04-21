import sys
import struct
import socket
import pprint
import optparse
import pprint
# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Enumerate All Investigations")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    return parser


def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # enumerate all watchlists 
    #
    investigations = cb.investigation()

    print "%-4s | %-32s | %-32s | %-32s | %-32s" % ('id', 'name','date_started','last_updated','notes')
    print "%-4s + %-32s | %-32s | %-32s | %-32s" % ('-' * 4, '-' * 32, '-' * 32,'-' * 32,'-' * 32)

    # for each result 
    for investigation in investigations:
        print "%-4s | %-32s | %-32s | %-32s | %s" % (investigation['id'], investigation['name'], investigation['date_started'],investigation['last_updated'],investigation['notes'] )
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
