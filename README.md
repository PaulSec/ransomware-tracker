Python API for [http://ransomwaretracker.abuse.ch/tracker/](http://ransomwaretracker.abuse.ch/tracker/)
========


Install requirements
========

```shell
pip install -r requirements.txt
```

Import the classes:

```python
from ransomwareTrackerAPI import RansomwareTracker
from ransomwareTrackerAPI import Threat
from ransomwareTrackerAPI import Malware
```

Then, you can start querying!

Usage
========

Fetching results from the front page
=========

```python
# will fetch the results on the first page
res = RansomwareTracker(True).retrieve_results()
print res
```
The output will be something like: 

```shell
$ python API_example.py | python -m simplejson.tool
{
    "matches": [
        {
            "date_added": "2017-02-03 06:53",
            "domain_registrar": "Eranet International Limited",
            "host": "p27dokhpz2n7nvgr.15jznv.top",
            "ip_adress": "23.163.0.113 ( United States)",
            "malware": "Cerber",
            "threat": "Payment Site"
        },
        {
            "date_added": "2017-02-02 22:10",
            "domain_registrar": "Eranet International Limited",
            "host": "p27dokhpz2n7nvgr.1cbcpy.top",
            "ip_adress": "23.163.0.113 ( United States)",
            "malware": "Cerber",
            "threat": "Payment Site"
        },
        ......
    ],
    "total": 100        
}
```

Fetching the second page:

```python
# will fetch the second page
res = RansomwareTracker(True).retrieve_results(page=2)
print res
```

The output will be in the exactly same format.


Filtering by Malware
=========

```python
# will fetch results for TesclaCrypt malwares
res = RansomwareTracker(True).retrieve_results(filter_with=Malware.TeslaCrypt)
print res
```

The output will be something like: 

```shell
$ python API_example.py | python -m simplejson.tool
{
    "matches": [
        {
            "date_added": "2016-05-08 21:29",
            "domain_registrar": "GODADDY.COM, LLC",
            "host": "jdebrains.com",
            "ip_adress": "23.229.155.72 ( United States)",
            "malware": "TeslaCrypt",
            "threat": "Botnet C&C"
        },
        {
            "date_added": "2016-05-08 21:29",
            "domain_registrar": "PDR LTD. D/B/A PUBLICDOMAINREGIS[...]",
            "host": "chaliawala.com",
            "ip_adress": "64.22.112.34 ( United States)",
            "malware": "TeslaCrypt",
            "threat": "Botnet C&C"
        },
        .......
    ],
    "total": 256        
}
```

The complete list (implemented as an Enum) of Malware is listed here:

```
TeslaCrypt
CryptoWall
TorrentLocker
PadCrypt
Locky
CTB_Locker
FAKBEN
PayCrypt
DMALocker
Cerber
```

Filtering by Threat
=========

```python
# will fetch C&C threats
res = RansomwareTracker(True).retrieve_results(filter_with=Threat.c2)
print res
```

The output will be something like: 

```shell
$ python API_example.py | python -m simplejson.tool
{
    "matches": [
        {
            "date_added": "2017-02-01 16:28",
            "domain_registrar": "",
            "host": "93.170.123.185",
            "ip_adress": "93.170.123.185 ( Czech Republic)",
            "malware": "Locky",
            "threat": "Botnet C&C"
        },
        {
            "date_added": "2017-01-29 01:18",
            "domain_registrar": "",
            "host": "88.214.237.45",
            "ip_adress": "88.214.237.45 ( Russian Federation)",
            "malware": "Locky",
            "threat": "Botnet C&C"
        },
        .......
    ],
    "total": 649
}
```

The complete list (implemented as an Enum) of Threat is listed here:

```
c2
payment_sites
distribution_sites
```

Contributing
=======

Feel free to open issues, contribute and submit your Pull Requests. Released under MIT License.
You can also ping me on Twitter ([@PaulWebSec](https://twitter.com/PaulWebSec))
