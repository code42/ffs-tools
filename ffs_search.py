import sys, requests, getpass, json, argparse

class FFSQuery:
    """
    FFSQuery provides a wrapper for creating FFS queries and returning results

    The FFS Query class provides a number of methods for logging into Code42, building a query,
    and conducting a search
    """

    def __init__(self, base_url):
        """
        Initialization method for FFSQuery

        :param base_url: Base URL for Code42 API queries
        :returns: Returns an FFSQuery object
        """
        # Create a new request session object to persist a session
        self.s = requests.Session()
        # Auth token used for querying
        self.auth_token = None
        # Query payload
        self.query_payload = {}
        # Flag if we are logged in
        self.logged_in = False
        # Set base URL for queries
        self.base_url = base_url
    

    def _get_login_config(self, sts_url, username):
        """
        Internal method to get the Code42 login configuration

        :param sts_url: URL for STS API calls
        :param username: Username for retrieving the login config
        :returns: Returns the login type for that username
        """
        url = 'https://{}/api/v1/LoginConfiguration?username={}'.format(sts_url, username)
        response = self.s.get(url)
        if response.status_code != 200:
            return "Failed"
        login_settings = json.loads(response.text)
        return login_settings['loginType']

    def _get_auth_token(self, sts_url, username, password):
        """
        Internal method to get the Code42 v3 auth tokent

        :param sts_url: URL for STS API calls
        :param username: Username to log in as
        :param password: Password for account
        :returns: Returns the v3 auth token if successful, or None if authenictaion has failed
        """
        url = 'https://{}/api/v1/login-user?username={}'.format(sts_url, username)
        response = self.s.get(url, auth=(username,password))
        if response.status_code != 200:
            return None
        return json.loads(response.text)['v3_user_token']
    
    def do_login(self, sts_url, username, password):
        """
        Login to the Code42 application

        :param username: Username to log in as
        :param password: Password for account
        :returns: Returns True if login was successful, False otherwise
        """
        # Get the login config
        login_config = self._get_login_config(sts_url,username)
        if login_config != 'LOCAL':
            return False
        # Get authentication token
        self.auth_token = self._get_auth_token(sts_url, username, password)
        if self.auth_token is None:
            return False
        else:
            # Toggle flag
            self.logged_in = True
            return True

    def build_query_payload(self, search_type, search_values):
        """
        Build a query payload based on search type and values

        :param search_type: Type of search you want to conduct, will be mapped to FFS API field types
        :param search_values: list of values to search for
        :returns: Returns True if the query build was successful
        """
        # Map out the supported search fields to FFS API field names
        mapper = {
            'md5': 'md5Checksum',
            'sha256': 'sha256Checksum',
            'filename': 'fileName',
            'hostname': 'osHostName',
            'filepath': 'filePath'
        }
        # If a master group does not exist in the query yet, add it.
        if 'groups' not in self.query_payload:
            self.query_payload['groups'] = []
        ffs_filters = {}
        for search_value in search_values:
            ffs_filter = {}
            ffs_filter['operator'] = "IS"
            ffs_filter['term'] = mapper[search_type]
            ffs_filter['value'] = search_value
            if 'filters' not in ffs_filters:
                ffs_filters['filters'] = []
            ffs_filters['filters'].append(ffs_filter)
        ffs_filters['filterClause'] = 'OR'
        self.query_payload['groups'].append(ffs_filters)
        self.query_payload['pgNum'] = 1
        self.query_payload['pgSize'] = 100
        return True

    def load_query_payload_from_json(self, json_payload):
        """
        Load a query payload from a JSON object.

        :param json_payload: JSON object that is a valid payload for the FFS API
        :returns: Returns True if the query load was successful
        """
        # Make sure the json_payload is a dict
        if isinstance(json_payload, dict):
            # Simply copy the payload into the query_payload variable
            self.query_payload = json_payload
            return True
        else:
            return False

    def do_search(self):
        """
        Conduct a search using FFS API.

        :returns: Returns the search result, or None if there is an error
        """
        if self.query_payload is None:
            return None
        url = 'https://{}/forensic-search/queryservice/api/v1/fileevent'.format(self.base_url)
        headers = {'authorization' : 'v3_user_token {}'.format(self.auth_token)}
        headers ['Content-Type'] = 'application/json'
        response = self.s.post(url,headers=headers, json=self.query_payload)
        if response.status_code != 200:
            return None
        return json.loads(response.text)

def read_in_file(in_file, search_type):
    try:
        value_file = open(in_file, "r")
        # If search type is raw, read the entire file and return the string, otherwise return a list
        if search_type == 'raw':
            return value_file.read()
        else:
            return value_file.read().splitlines()
    except:
        return None

def write_out_json(out_file, results):
    try:
        print('Writing results to file {}...'.format(out_file))
        results_file = open(out_file, "w+")
        json.dump(results, results_file, indent=4)
        print('Write complete!')
        return 0
    except:
        return 1

def write_out_count(out_file, count):
    try:
        print('Writing count to file {}...'.format(out_file))
        results_file = open(out_file, "w+")
        results_file.write(str(count))
        print('Write complete!')
        return 0
    except:
        return 1

def filter_results(results, out_filter):
    newresults = []
    mapper = {
        'md5': 'md5Checksum',
        'sha256': 'sha256Checksum'
    }
    for event in results['fileEvents']:
        # Grab the attribute based on the mapping between out_filter options and the actual attribute name
        newresults.append(event[mapper[out_filter]])
    return newresults
    
    
def main():
    # Define args
    parser = argparse.ArgumentParser(description='Code42 File Forensic Search')
    parser.add_argument('--username', help='Local user for with Security Event Viewer rights', required=True)
    parser.add_argument('--password', help='Local user password')
    parser.add_argument('--sts_url', default='sts-east.us.code42.com', help='STS URL for retrieving authentication token, defaults to sts-east')
    parser.add_argument('--base_url', default='forensicsearch-east.us.code42.com', help='API URL for search, defaults to forensicsearch-east')
    parser.add_argument('--search_type', choices = ['md5', 'sha256', 'filename', 'filepath', 'hostname', 'raw'], help='Type of attribute to search for. A raw search will take a JSON string as a value and use that as the query payload for complex queries', required=True)
    parser.add_argument('--values', nargs='*', help='One or more values of attribute search_type to search for', metavar=('value1', 'value2'))
    parser.add_argument('--count', help='Return count of results only', dest='count_only', action='store_true')
    parser.add_argument('--in_file', help='Input file containing values (one per line) or raw JSON query payload')
    parser.add_argument('--out_file', help='Output file for results')
    parser.add_argument('--out_filter', choices = ['md5','sha256'], help='Selected attribute to export instead of all attributes for each event')

    # Parse passed args
    args = parser.parse_args()
    # Sanity checks for options
    if args.values is None and args.in_file is None:
        print('Error: You must pass either one more --values or an --in_file with values to search. Quitting...')
        sys.exit()
    if args.values and len(args.values) > 1024:
        print('Error: There is a limit of 1024 values per query, you have {} values. Quitting...'.format(len(args.values)))
        sys.exit()
    if args.count_only and args.out_filter:
        print('Error: --count and --out_filter are mutually exclusive options. Quitting...')
        sys.exit()

    
    # Parse in_file if passed, otherwise read Values
    if args.in_file:
        query_values = read_in_file(args.in_file, args.search_type)
        if query_values is None:
            print('Error parsing values in in_file. Quitting...')
            sys.exit()
    else:
        if args.search_type == 'raw':
            query_values = args.values[0]
        else:
            query_values = args.values
    
    # Get password if it is not passed on the command line
    if args.password is None:
        password = getpass.getpass('Enter password for account {}:'.format(args.username))
    else:
        password = args.password
    
    # Create FFSQuery object
    ffs_query = FFSQuery(args.base_url)
    response = ffs_query.do_login(args.sts_url, args.username, password)
    if not response:
        print('Could not log in. Quitting...')
        sys.exit()
    # Build query payload
    if args.search_type == 'raw':
        # Covert the raw value to a JSON object
        try:
            response = ffs_query.load_query_payload_from_json(json.loads(query_values))
        except Exception as e:
            print('Error parsing JSON input, message: \'{}\'. Quitting...'.format(str(e)))
            sys.exit()
    else:
        ffs_query.build_query_payload(args.search_type, query_values)
    # Do the search
    results = ffs_query.do_search()
    if results is None:
        print('Error returning results. Quitting...')
        sys.exit()
    # Filter results if there is an out_filter
    if args.out_filter:
        results = filter_results(results, args.out_filter)

    # If --count is selected, just return the count
    if args.count_only:
        # If --out_file is specified, output to file, otherwise print to stdout
        if args.out_file:
            success = write_out_count(args.out_file,results['totalCount'])
            if success != 0:
                print('Error writing out_file. Quitting...')
                sys.exit()
        else:
        # Print results
            print(results['totalCount'])
    else:
        # If --out_file is specified, output to file, otherwise print to stdout
        if args.out_file:
            success = write_out_json(args.out_file,results)
            if success != 0:
                print('Error writing out_file. Quitting...')
                sys.exit()
        else:
        # Print results
            print(json.dumps(results, indent=4, sort_keys=True))

if __name__=='__main__':
    main()
