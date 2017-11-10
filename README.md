# README

sslxray is an SSL/TLS analysis tool designed to identify errors in the implementation and configuration of SSL/TLS. It is currently being developed by [Graham Sutherland](https://github.com/gsuberland).

Written in Python, heavily utilising a modified version of tlslite - https://pypi.python.org/pypi/tlslite

The long-term development plan is to build a local script which does everything that the Qualys SSL Labs scanner does, and a bit more.

## INSTALLATION

Prerequisites:

* The included version of tlslite has been heavily modified. Do not try to use the original library!
* Python 2.7
* M2Crypto python library (`pip install m2crypto`)
* pycrypto python library (`pip install pycrypto`)
* hexdump python library (`pip install hexdump`) when running in debug mode
* GMP and GMPY are optional but recommended for speed (`apt-get install python-gmpy`).

Note that some of these require an up-to-date version of pip (8.x) and setuptools (20.x) which can be installed via:
* `python -m pip install --upgrade pip`
* `python -m pip install --upgrade setuptools`

Additionally, you may need the following prerequisites to install M2Crypto properly:
* libssl-dev
* python-dev

Windows bugs:

* M2Crypto has a Windows package (m2cryptowin32 / m2cryptowin64) which must match the bitness of your Python install (usually 32-bit).
* If you get an error about --single-version-externally-managed when installing M2Crypto, use `pip install --egg m2cryptowin32`
* pycrypto's installer requires Microsoft Visual C++ Compiler for Python, available here: http://aka.ms/vcpython27

## CURRENT FEATURES

Version 0.1.5 supports the following features:

* Manual SNI selection
* SSL/TLS cipher suite enumeration, including TLSv1.3 draft support
* Per-bit MAC validation checks
* ServerRandom randomness checks
* Elliptic curve support detection
* ALPN and NPN feature detection

## KNOWN BUGS/ISSUES

* SNI is set to empty by default. On some servers (e.g. CloudFlare stuff) this results in no ciphers being supported. Use `-S <hostname>` to fix this.
* SSLv2.0 support is currently tentative, and only works on servers which accept a SSLv2.0 version field on SSLv3/TLS packet format.
* Randomness tests on ServerRandom are rudimentary and a bit slow (although better as of 0.1.4)
* Certain flags haven't been fully tested with each other yet and might have weird consequences.
* Almost no handling of server timeouts at the moment.

## IMMEDIATE DEVELOPMENT

The following features are immediately planned:

* Proper SSLv2 packet support
* SCSV extension support detection
* Padding bit validation checks
* Full suite enumeration (0x0000 to 0xFFFF)
* X.509 parsing and validation checks (e.g. expiry, RSA key size, CA chain)
* Broken/bad/known certificate checks (e.g. Debian OpenSSL stack contents bug)
* Common DH prime checks
* Weak / sketchy DH group detection
* Reporting and logging/output engine

## FUTURE DEVELOPMENT

The following features will be implemented in future, pending feasibility:

* Superfluous chain checking on certs
* Support for DSA certificates
* Ability to save all traffic sent/recv to a pcap
* PCI mode (checking compliance with PCI guidelines)
* Client certificate support
* Other stuff from Qualys SSL Scan

## CONTRIBUTION GUIDELINES

Pull requests and bug reports welcome.

If you want to push code to sslxray, please adhere to the following guidelines:

General:

* Please make sure your check actually works! (and not just against Google and Amazon)
* I use PyCharm 5, I suggest you do too.
* If you're adding new files, please do so via PyCharm IDE, or let me know so I can properly update the project file.
* Per change, update the version number by 0.0.1, and wrap such that 0.1.9 + 0.0.1 becomes 0.2.0
* Update the changelog below
* If you push a commit, write a sensible and informative commit message.

Style:

* Comment your code. Every function and class needs a documenting comment, including rtype and return comments where applicable. See existing code for style.
* An indent is four ASCII spaces (0x20 * 4), not a tab character or any other delimiter.
* Functions are separated by two newlines.
* Use single line breaks in functions to break up logical sections and operations.
* Double-quotes for strings, unless they're for inline dictionary keys, in which case use single quotes, i.e. foo['bar']
* If you think you need a global constant, you probably need a new entry for argparse instead, so that the user can customise it.
* All constants, global or local, should use CAPITAL_LETTERS for styling.
* Use Python 3.x style printing. The print function has been imported from __future__ so make sure to use print("foo") with parentheses, not spaces.

If you're not sure, check existing style for precedent.

## CHANGELOG

Version 0.1.5:
* Project renamed from original codename to 'sslxray'
* Added NPN support check.
* Added ALPN support check.
* Improved ServerRandom randomness checks.

Version 0.1.4:
* Added -S flag for specifying SNI hostname (contrib from [Mark Lowe](https://github.com/pentestmonkey/))
* Fixed bug where SSLv2.0 header would be sent for non-SSLv2 headers.
* Improved ServerRandom randomness checks.
* Added enumeration of elliptic curve support on all cipher suites which use ECDH/ECDHE.

Version 0.1.3:
* First internally published version. Rough cut but probably useful.
* Added ServerRandom randomness checks.
* Added ability to disable checks on certain protocols.

Version 0.1.2:
* Improved error handling.
* Added --list-suites and --list-protocols switches.

Version 0.1.1:
* Added support for MAC fuzzing.
* Fixed oversight where weird suites (e.g. PCT stuff) with ID > 0xFFFF being scanned for.

Version 0.1.0:

* Initial functioning alpha.
