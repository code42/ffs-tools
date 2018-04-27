import sys, requests, getpass, json, argparse

def get_login_config(session, sts_url, username):
    url = 'https://{}/api/v1/LoginConfiguration?username={}'.format(sts_url, username)
    response = session.get(url)
    if response.status_code != 200:
        return "Failed"
    login_settings = json.loads(response.text)
    return login_settings['loginType']

def get_auth_token(session, sts_url, username, password):
    url = 'https://{}/api/v1/login-user?username={}'.format(sts_url, username)
    response = session.get(url, auth=(username,password))
    if response.status_code != 200:
        return None
    return json.loads(response.text)['v3_user_token']

def build_query_payload(ffs_query, search_type, search_values):
    mapper = {
        'md5': 'md5Checksum',
        'filename': 'fileName',
        'hostname': 'osHostName',
        'filepath': 'filePath'
    }
    if 'groups' not in ffs_query:
        ffs_query['groups'] = []
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
    ffs_query['groups'].append(ffs_filters)
    ffs_query['pgNum'] = 1
    ffs_query['pgSize'] = 100
    return ffs_query

def do_search(session, base_url, payload, auth_token):
    url = 'https://{}/forensic-search/queryservice/api/v1/fileevent'.format(base_url)
    headers = {'authorization' : 'v3_user_token {}'.format(auth_token)}
    headers ['Content-Type'] = 'application/json'
    response = session.post(url,headers=headers, json=payload)
    if response.status_code != 200:
        print('Error in query, message \'{}\'.'.format(response.text))
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
        'md5': 'md5Checksum'
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
    parser.add_argument('--base_url', default='authority-east-lb.us.code42.com', help='API URL for search, defaults to authority-east-lb')
    parser.add_argument('--search_type', choices = ['md5', 'filename', 'filepath', 'hostname', 'raw'], help='Type of attribute to search for. A raw search will take a JSON string as a value and use that as the query payload for complex queries', required=True)
    parser.add_argument('--values', nargs='*', help='One or more values of attribute search_type to search for', metavar=('value1', 'value2'))
    parser.add_argument('--count', help='Return count of results only', dest='count_only', action='store_true')
    parser.add_argument('--in_file', help='Input file containing values (one per line) or raw JSON query payload')
    parser.add_argument('--out_file', help='Output file for results')
    parser.add_argument('--out_filter', choices = ['md5'], help='Selected attribute to export instead of all attributes for each event')

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
    
    s = requests.Session()
    # Get the login config
    login_config = get_login_config(s,args.sts_url,args.username)
    if login_config != 'LOCAL':
        print('Could not get config or user is not LOCAL, message: {}'.format(login_config))
        sys.exit()
    # Get authentication token
    auth_token = get_auth_token(s, args.sts_url, args.username, password)
    if auth_token is None:
        print('Could not retrieve auth token. Quitting...')
        sys.exit()
    # Build query payload
    ffs_query = {}
    if args.search_type == 'raw':
        # Covert the raw value to a JSON object
        try:
            ffs_query = json.loads(query_values)
        except Exception as e:
            print('Error parsing JSON input, message: \'{}\'. Quitting...'.format(str(e)))
            sys.exit()
    else:
        ffs_query = build_query_payload(ffs_query, args.search_type, query_values)
    # Do the search
    results = do_search(s, args.base_url, ffs_query, auth_token)
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
