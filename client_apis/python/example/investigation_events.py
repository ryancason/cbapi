mport sys
import struct
import socket
import pprint
import optparse
import pprint
# in the github repo, cbapi is not in the example directory
sys.path.append('../src/cbapi')

import cbapi

def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Dump Investigation Events")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-i", "--id", action="store", default=None, dest="id",
                      help="ID to Enumerate Investigation Events")
    return parser


def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.url or not opts.token or not opts.id:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    # build a cbapi object
    #
    cb = cbapi.CbApi(opts.url, token=opts.token, ssl_verify=opts.ssl_verify)

    # enumerate Invesigation 
    #
    investigations = cb.investigation(opts.id)

    # for each investigation 
    for investigation in investigations:
       pprint.pprint(investigation)
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
