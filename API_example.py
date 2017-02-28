from ransomwareTrackerAPI import RansomwareTracker
from ransomwareTrackerAPI import Threat
from ransomwareTrackerAPI import Malware

res = RansomwareTracker(True).retrieve_results()
print res

res = RansomwareTracker(True).retrieve_results(page=2)
print res

res = RansomwareTracker(True).retrieve_results(filter_with=Malware.TeslaCrypt)
print res

res = RansomwareTracker(True).retrieve_results(filter_with=Threat.c2)
print res

res = RansomwareTracker(True).search('.xyz')
print res
