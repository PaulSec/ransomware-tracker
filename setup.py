from distutils.core import setup
setup(
  name = 'ransomwaretracker',
  packages = ['ransomwaretracker'], # this must be the same as the name above
  version = '0.1',
  description = 'DNS Dumpster lib',
  author = 'Paul Sec',
  author_email = 'paulwebsec@gmail.com',
  url = 'https://github.com/PaulSec/ransomware-tracker',
  download_url = 'https://github.com/PaulSec/ransomware-tracker/tarball/0.1',
  keywords = ['ransomwaretracker', 'ransomware', 'tracker', 'requests'],
  install_requires=["bs4"],
  classifiers = [],
)