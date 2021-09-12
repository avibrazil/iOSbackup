# Changelog for iOSbackup

## v0.9.921...v0.9.913
* version bump
* typos in build system
* isOlderThaniOS10dot2() converted to a class static method
* plist handling with NSKeyedUnArchiver
* more items in the list of interesting files on README.md
* updated changelog

## v0.9.913...v0.9.912
* improved exception message when password of decryption key is wrong
* Merge pull request #13 from Unbrick/master
* Merge pull request #10 from hcleves/ios-older-than-10.2
* Merge pull request #7 from lps-rocks/patch-1
* Updated mmap to run on Windows machines
* Add files via upload
* Fix uncaught exception
* crypto donation addresses

## v0.9.912...v0.9.910
* included close() method to clean open databases
* started to use the logging module
* improved getFileDecryptedCopy() to handle huge files

## v0.9.910...v0.9.904
* getFileDecryptedCopy() now can handle huge files
* more code adaptation to acomodate improved getFileDecryptedCopy()
* taking care of other 2 catalog files: Info.plist and Status.plist
* improvements to examples as docs

## v0.9.904...v0.9.903
* New method getRelativePathDecryptedData
* doc section about basic device and backup info
* script to generate changelog from git-log

## v0.9.903...v0.9.902
* getFileDecryptedCopy() now sets file modification time corretcly to what is on device, localtime
* getFolderDecryptedCopy() sets files modification time as localtime, not UTC anymore
* getFileDecryptedData() includes entire manifest struct
* info about iTunes default backup folders
* assured to run with iOS 14 and updated README

## v0.9.902...v0.9.901
* added example for entire app files retrieval
* adapted getFolderDecryptedCopy to extract entire apps files

## v0.9.901...v0.9.9
* better explanations about derived key instead of clear text password
* removed pycrypto references from documentation
* migrated from pycrypto to pycryptodome
* how to use on a Linux host
* nicer docs
* Fix decryption padding from https://github.com/avibrazil/iOSbackup/issues/1

## v0.9.9...v0.9.2
* Make fastpbkdf2 dependency optional and dynamic; fallback to hashlib otherwise

## v0.9.2...v0.9.1
* added various datetime conversion and manipulation functions
* added more interesting files to documentation
