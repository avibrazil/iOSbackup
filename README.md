# iOSbackup

A Pyhotn 3 class that reads and extracts files from a **password-encrypted iOS backup** created by iTunes on Mac and Windows. Compatible with iOS 13.

You will need your backup password to decrypt the backup files, this is the password iTunes asks when it is configured to do encrypted backups. You should always prefer encrypted backups because they are more secure and include more files from your device. Non-encrypted backups do not backup files as Health app database and other preciosities.

## Installation

```shell
pip3 install iOSbackup --user
```

On macOS, get native Python 3 from Apple with command `xcode-select --install`. Read my [Apple official Python 3 distribution guide](https://avi.alkalay.net/2019/12/macos-jupyter-data-science-no-anaconda.html) for more details.

If installation fails, thats because of `pycrypto`. On macOS with Apple official Python 3 distribution, install `pycrypto` like this:

```shell
CFLAGS="-I/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.7/include" \
LDFLAGS="-L/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.7/lib" \
pip3 install pycrypto --user
```

Then install `iOSbackup`.

Other pre-requisites are `biplist` and `fastpbkdf2` that will be installed automatically by `pip`.


## Usage

### Get list of backups available on your computer
```python
>>> from iOSbackup import iOSbackup

>>> iOSbackup.getDeviceList()
[{'udid': '00456030-000E4412342802E',
  'name': 'mobileavi',
  'ios': '13.2.3',
  'serial': 'DNPPQRS0N4RW',
  'type': 'iPhone12,3',
  'encrypted': True},
{'udid': '00654030-01234412342802E',
  'name': 'ipad',
  'ios': '13.1.3',
  'serial': 'DABCRS0N4RW',
  'type': 'iPad10,1',
  'encrypted': True}]
```

### Open a device backup

With your password (a lengthy process):
```python
>>> b=iOSbackup(udid="00456030-000E4412342802E", cleartextpassword="mypassword")
```

Or with a saved derived key (much faster):
```python
>>> b=iOSbackup(udid="00456030-000E4412342802E", derivedkey="dd6b6123494c5dbdff7804321fe43ffe1babcdb6074014afedc7cb47f351524")
```

Forcing a backup folder, useful when reading backups on Linux, where there is no standard for backup folders:
```python
>>> b=iOSbackup(udid="00456030-000E4412342802E", cleartextpassword="mypassword", backuproot="/home/myuser/itunesfiles")
```

Get a list of backed-up files:
```python
>>> b.getBackupFilesList()
[{'name': '',
  'backupFile': 'abfbc8747bfbb373e2b08ce67b1255ffda4e1b91',
  'domain': 'AppDomain-4GU63N96WE.com.p5sys.jumpdesktop'},
 {'name': 'Documents',
  'backupFile': 'ec0c1b379560bb5ccc81ee783538fd51cfd97461',
  'domain': 'AppDomain-4GU63N96WE.com.p5sys.jumpdesktop'},
 {'name': 'Documents/Servers',
  'backupFile': 'a735380eade71b48f0fe27d38a283aacd8ed8372',
  'domain': 'AppDomain-4GU63N96WE.com.p5sys.jumpdesktop'},
 {'name': 'Documents/extensions',
  'backupFile': 'c08f725cc39ec819ab7ced3b056f4e0630ead09f',
  'domain': 'AppDomain-4GU63N96WE.com.p5sys.jumpdesktop'},
 {'name': 'Library',
  'backupFile': 'e60a6345697594c735e5a6ed86c0d57dad6a2176',
  'domain': 'AppDomain-4GU63N96WE.com.p5sys.jumpdesktop'},
 ...]
```

`backupFile` is the file name on your computer. Basically SHA1([Domain]/[FilePath]).

`name` is the original semi-complete path of file name in the device.

`domain` is the file group this file is member, see bellow list of domains.

Or put it directly into a Pandas DataFrame for easier manipulation and searching:
```python
import pandas as pd
>>> backupfiles=pd.DataFrame(b.getBackupFilesList(), columns=['backupFile','domain','name'])
```

With Pandas, display only list of files in `HomeDomain` group:
```python
>>> backupfiles[backupfiles['domain']=='HomeDomain']
```

Get a decrypted copy of the call history SQLite database:
```python
>>> file=b.getFileDecryptedCopy(relativePath="Library/CallHistoryDB/CallHistory.storedata")
>>> file
{'decryptedFilePath': 'HomeDomain~Library--CallHistoryDB--CallHistory.storedata',
 'domain': 'HomeDomain',
 'originalFilePath': 'Library/CallHistoryDB/CallHistory.storedata',
 'backupFile': '5a4935c78a5255723f707230a451d79c540d2741',
 'size': 1228800}
```

Read decrypted copy of call history database:
```python
>>> calls = sqlite3.connect(self.decryptedFilePath)
>>> calls.row_factory=sqlite3.Row
>>> calllog = calls.cursor().execute(f"SELECT * FROM ZCALLRECORD ORDER BY ZDATE DESC").fetchall()
```

## Pre-requisites

```shell
pip3 install biplist --user
pip3 install fastpbkdf2 --user
```

On macOS with [Apple official Python 3 distribution](https://avi.alkalay.net/2019/12/macos-jupyter-data-science-no-anaconda.html), install `pycrypto` like this:
```shell
CFLAGS="-I/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.7/include" \
LDFLAGS="-L/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.7/lib" \
pip3 install pycrypto --user
```

## Apple-native Python 3 Installation on Macs

Follow my guide at https://avi.alkalay.net/2019/12/macos-jupyter-data-science-no-anaconda.html

Basically use command `xcode-select --install` to get Python 3 installed and updated by Apple on your Mac.

## List of Domains

Domain | Contains
--- | ---
**AppDomain-...** | Backup of each installed app's files
**CameraRollDomain** | Photos
**DatabaseDomain** |
**HealthDomain** | Health app databases
**HomeDomain** | Many interesting databases, such as call history
**HomeKitDomain** |
**InstallDomain** |
**KeyboardDomain** |
**KeychainDomain** |
**ManagedPreferencesDomain** |
**MediaDomain** |
**MobileDeviceDomain** |
**RootDomain** |
**SysContainerDomain-com.apple.Preferences.SettingsSpotlightIndexExtension** |
**SysContainerDomain-com.apple.Preferences.indexSettingsManifests** |
**SysContainerDomain-com.apple.accessibility.AccessibilityUIServer** |
**SysContainerDomain-com.apple.adid** |
**SysContainerDomain-com.apple.akd** |
**SysContainerDomain-com.apple.appstored** |
**SysContainerDomain-com.apple.apsd** |
**SysContainerDomain-com.apple.backboardd** |
**SysContainerDomain-com.apple.fairplayd.H2** |
**SysContainerDomain-com.apple.geod** |
**SysContainerDomain-com.apple.icloud.findmydeviced** |
**SysContainerDomain-com.apple.icloud.ifccd** |
**SysContainerDomain-com.apple.icloud.searchpartyd** |
**SysContainerDomain-com.apple.lsd** |
**SysContainerDomain-com.apple.lskdd** |
**SysContainerDomain-com.apple.metrickitd** |
**SysContainerDomain-com.apple.mobilesafari** | Bookmarks and cookies ?
**SysContainerDomain-com.apple.springboard** |
**SysSharedContainerDomain-systemgroup.com.apple.AssetCacheServices.diskCache** |
**SysSharedContainerDomain-systemgroup.com.apple.DiagnosticsKit** |
**SysSharedContainerDomain-systemgroup.com.apple.ReportMemoryException** |
**SysSharedContainerDomain-systemgroup.com.apple.VideoSubscriberAccount** |
**SysSharedContainerDomain-systemgroup.com.apple.WiFiAssist** |
**SysSharedContainerDomain-systemgroup.com.apple.bluetooth** |
**SysSharedContainerDomain-systemgroup.com.apple.cfpreferences.managed** |
**SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles** |
**SysSharedContainerDomain-systemgroup.com.apple.coreanalytics** |
**SysSharedContainerDomain-systemgroup.com.apple.icloud.findmydevice.managed** |
**SysSharedContainerDomain-systemgroup.com.apple.icloud.fmipcore.MockingContainer** |
**SysSharedContainerDomain-systemgroup.com.apple.icloud.ifccd** |
**SysSharedContainerDomain-systemgroup.com.apple.icloud.searchpartyd.sharedsettings** |
**SysSharedContainerDomain-systemgroup.com.apple.itunesu.shared** |
**SysSharedContainerDomain-systemgroup.com.apple.lsd** |
**SysSharedContainerDomain-systemgroup.com.apple.lsd.iconscache** |
**SysSharedContainerDomain-systemgroup.com.apple.lskdrl** |
**SysSharedContainerDomain-systemgroup.com.apple.media.books.managed** |
**SysSharedContainerDomain-systemgroup.com.apple.media.shared.books** |
**SysSharedContainerDomain-systemgroup.com.apple.mobile.installationhelperlogs** |
**SysSharedContainerDomain-systemgroup.com.apple.mobilegestaltcache** |
**SysSharedContainerDomain-systemgroup.com.apple.nsurlstoragedresources** |
**SysSharedContainerDomain-systemgroup.com.apple.ondemandresources** |
**SysSharedContainerDomain-systemgroup.com.apple.osanalytics** |
**SysSharedContainerDomain-systemgroup.com.apple.sharedpclogging** |
**SystemPreferencesDomain** |
**TonesDomain** |
**WirelessDomain** |

## Interesting Files

Backup file | Domain | File name | Contains
--- | --- | --- | ---
ed1f8fb5a948b40504c19580a458c384659a605e | WirelessDomain | Library/Databases/CellularUsage.db | Table `subscriber_info` apparently contains all SIM phone numbers ever inserted in the phone since about iOS 11 or 12
0d609c54856a9bb2d56729df1d68f2958a88426b | WirelessDomain | Library/Databases/DataUsage.sqlite | A rich database that apparently contains app WWAN usage through time. Chack tables `ZPROCESS` and `ZLIVEUSAGE`.
1570a95f5dc7f4cd6b54bc17c427eda95288b8fa | HomeDomain | Library/SpringBoard/LockVideo.mov | Video used as background on lock screen
- | HomeDomain | Library/Passes/Cards/* | Wallet passes and items
8d0167b67f664a3816b4c00115c2dfa6a8f81388 |WirelessDomain | Library/Preferences/com.apple.AppleBasebandManager.Statistics.plist | Apparently contains times of last boot and restores.
dafec408e48be2700704dd3e763014c39f6de6b3 | WirelessDomain | Library/Preferences/com.apple.AppleBasebandManager.plist
9329979c8298f9cd3fb110fa387570a8b957e912 | WirelessDomain | Library/Preferences/com.apple.CommCenter.counts.plist | Has `CellularBytesRecved` and `CellularBytesSent`
3dec38ca46c9e37ffebacf2611463eb47a65eb09 | WirelessDomain | Library/Preferences/com.apple.commcenter.audio.plist
7e5f642f6da5e2345c0893bdf944da9c53902756 | WirelessDomain | Library/Preferences/com.apple.commcenter.callservices.plist
bfecaa9c467e3acb085a5b312bd27bdd5cd7579a | WirelessDomain | Library/Preferences/com.apple.commcenter.plist | Cellular network informations and configurations.
160600e9c2e408c69e4193d325813a2a885bce2a | WirelessDomain | Library/Preferences/com.apple.ipTelephony.plist
- | HomeDomain | Library/Mobile Documents/iCloud~... | Apps documents on iCloud
- | HomeDomain | Library/Mobile Documents/com\~apple\~CloudDocs/... | Documents folder on iCloud
5a4935c78a5255723f707230a451d79c540d2741 | HomeDomain | Library/CallHistoryDB/CallHistory.storedata | Call History database with only the last 600 calls
31bb7ba8914766d4ba40d6dfb6113c8b614be442 | HomeDomain | Library/AddressBook/AddressBook.sqlitedb | User contacts and address book. Table `ABPerson` is the central one with facts about contact creation and modification, while `ABMultiValue*` tables contain contact details.
cd6702cea29fe89cf280a76794405adb17f9a0ee | HomeDomain | Library/AddressBook/AddressBookImages.sqlitedb | Contact photos
9db3e5a6f1672cc306cd785809811e79cc43a2f8 | HomeDomain | Library/AddressBook/backup/AddressBook.sqlitedb
2a87d5bcdb9753f1462dd1e929b17e6a971c5b01 | HomeDomain | Library/AddressBook/backup/AddressBookImages.sqlitedb