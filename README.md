# FFS Search Tool

### Summary
Searches for Forensic File Search events in Code42 FFS tool via API

### Requirements

FFS Search Tool requires Python 3 and the following packages (install via pip):

* Requests

### Usage
```
usage: ffs_search.py [-h] --username USERNAME [--password PASSWORD]
                     [--sts_url STS_URL] [--base_url BASE_URL] --search_type
                     {md5,sha256,filename,filepath,hostname,raw}
                     [--values [value1 [value2 ...]]] [--count]
                     [--in_file IN_FILE] [--out_file OUT_FILE]
                     [--out_filter {md5,sha256}]

Code42 Forensic File Search

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME   Local user for with Security Event Viewer rights
  --password PASSWORD   Local user password
  --sts_url STS_URL     STS URL for retrieving authentication token, defaults
                        to sts-east
  --base_url BASE_URL   API URL for search, defaults to authority-east-lb
  --search_type {md5,sha256,filename,filepath,hostname,raw}
                        Type of attribute to search for. A raw search will
                        take a JSON string as a value and use that as the
                        query payload for complex queries
  --values [value1 [value2 ...]]
                        One or more values of attribute search_type to search
                        for
  --count               Return count of results only
  --in_file IN_FILE     Input file containing values (one per line) or raw
                        JSON query payload
  --out_file OUT_FILE   Output file for results
  --out_filter {md5,sha256}
                        Selected attribute to export instead of all attributes
                        for each event
```

### CLI Examples

#### Search for single Hostname
```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type hostname --values C02RW2N1FVH0
```

#### Search for multiple MD5 hashes on the command line (up to 1024 values per search)
```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type md5 --values d79d4f630f6e74d12305ce61268c125b eb574631669f4c00a2d49c4e051ccaad
```

#### Conduct a custom search using a JSON payload
Note: see the [API Documentation](https://support.code42.com/Administrator/Cloud/Monitoring_and_managing/Forensic_File_Search_API) support page for complete information on search syntax.

```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type raw --values '{
  "groups": [
    {
      "filters": [
        {
          "operator": "IS",
          "term": "fileName",
          "value": "*.docm"
        },
        {
          "operator": "IS",
          "term": "fileName",
          "value": "*.xlsm"
        }
      ],
      "filterClause": "OR"
    },
    {
      "filters": [
        {
          "operator": "IS",
          "term": "filePath",
          "value": "C:\\Users\\*\\Downloads*"
        },
        {
          "operator": "IS",
          "term": "eventType",
          "value": "CREATED"
        }
      ],
      "filterClause": "AND"
    }
  ],
  "groupClause": "AND",
  "pgNum": 1,
  "pgSize": 100,
  "srtDir": "desc",
  "srtKey": "eventTimestamp"
}'
```

#### Conduct a custom search from a JSON file
Conducts the same search as above assuming that example\_macro\_download\_files.json contains the above JSON

```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type raw --in_file example_macro_download_files.json
```

#### Write search results to file
```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type md5 --values d79d4f630f6e74d12305ce61268c125b --out_file results.json
```

#### Return count of results only
```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type md5 --values d79d4f630f6e74d12305ce61268c125b --count
```

#### Export only the SHA256 hashes from a search
```
python3 ./ffs_search.py --username sampleuser@code42.com --search_type raw --values example_macro_download_files.json --out_file results.json --out_filter sha256
```

### FFSQuery Class Examples

You can also import the FFSQuery class into your own Python code:

```
from ffs_search import FFSQuery
q = FFSQuery('authority-east-lb.us.code42.com')
q.do_login('sts-east.us.code42.com','sampleuser@code42.com','************')
q.build_query_payload('md5',['7bf2b57f2a205768755c07f238fb32cc'])
results = q.do_search()
```

### Future Enhancements
* Support searching on all event types
* More complex queries without the need for raw search_type
* Filter output results
* Better error handling/messaging
