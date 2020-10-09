# iOSbackup

A Python 3 class that reads and extracts files from a **password-encrypted iOS backup** created by iTunes on Mac and Windows. Compatible with iOS 13 and iOS 14.

You will need your backup password to decrypt the backup files, this is the password iTunes asks when it is configured to do encrypted backups. This password can be found on macOS' Keychain Access app, under `login` keychain, entry `iOS Backup`. 

You should always prefer encrypted backups because they are more secure and include more files from your device. Non-encrypted backups do not backup files as Health app database and other preciosities.

## Installation

```shell
pip3 install iOSbackup --user
```

On macOS, get native Python 3 from Apple with command `xcode-select --install`. Read my [guide to install Apple official Python 3 distribution](https://avi.alkalay.net/2019/12/macos-jupyter-data-science-no-anaconda.html) for more details.

`iOSbackup` requires other two packages: `biplist` and `pycryptodome` that will be [installed automatically by `pip`](https://pypi.org/project/iOSbackup/).

`pycryptodome` has an API compatible with older `pycrypto`, which should also work with `iOSbackup`. But `pycryptodome` is more well maintained and easier to install on Windows and macOS.


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

With your password (a slow and compute-intensive task):
```python
>>> b=iOSbackup(
	udid="00456030-000E4412342802E",
	cleartextpassword="mypassword"
)
```
Instead of a clear text password, use a derived key that can be seen into the instantiated object:
```python
>>> b=iOSbackup(
	udid="00456030-000E4412342802E",
	cleartextpassword="mypassword"
)
>>> print(b)
…
decryptionKey: dd6b6123494c5dbdff7804321fe43ffe1babcdb6074014afedc7cb47f351524
…
```
From now on use your derived key instead of your clear text password to not expose it and because it is much faster:
```python
>>> b=iOSbackup(
	udid="00456030-000E4412342802E",
	derivedkey="dd6b6123494c5dbdff7804321fe43ffe1babcdb6074014afedc7cb47f351524"
)
```
### Linux virtual machine accessing iOS backup on a macOS host

Forcing a backup folder, useful when reading backups on Linux, where there is no standard for backup folders:
```python
>>> b=iOSbackup(
	udid="00456030-000E4412342802E",
	cleartextpassword="mypassword",
	backuproot='/media/sf_username/Library/Application Support/MobileSync/Backup'
)
```
For this to work on a Linux virtual machine accessing a VirtualBox-shared folder, you'll have to grant full disk access to your hypervisor (VirtualBox etc).
On macOS, go to *System Preferences* ➔ *Security & Privacy* ➔ *Privacy* ➔ *Full Disk Access* and enable access to your hypervisor (VirtualBox etc).
The hypervisor and VM will have to be restarted for the new setting to be effective.

You can also copy your device's backup folder, from a Windows or macOS computer, to a Linux computer, and then use this class on Linux to decrypt and read it.

### iTunes default backup folders on Windows and macOS

Files app (formerly iTunes) on macOS stores backups of associated devices under `~/Library/Application Support/MobileSync/Backup`.
iTunes on Windows stores backups of associated devices under `%HOME%\Apple Computer\MobileSync\Backup`

### Get a list of backed-up files:
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

### Get a decrypted copy of the call history SQLite database:
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
>>> calls = sqlite3.connect(file.decryptedFilePath)
>>> calls.row_factory=sqlite3.Row
>>> calllog = calls.cursor().execute(f"SELECT * FROM ZCALLRECORD ORDER BY ZDATE DESC").fetchall()
```

### Restore Entire Folder Containing _Photos_ and their Metadata
This content is located in the `Media` folder of `CameraRollDomain` domain.
This example will exclude videos from restoration.
```python
>>> b.getFolderDecryptedCopy(
	'Media',
	targetFolder='restored-photos',
	includeDomains='CameraRollDomain',
	excludeFiles='%.MOV'
)
```

### Get List of All Installed Apps
```python
>>> apps=list(b.manifest['Applications'].keys())
>>> apps
['group.com.apple.Maps',
 'group.net.whatsapp.family',
 'it.joethefox.XBMC-Remote',
 'com.google.GoogleMobile.NotificationContentExtension',
 'group.com.dendrocom.uniconsole',
 ...
]
```

### Get List of All Apps, Groups and Plugins with “_whatsapp_” In Their Name
```python
>>> [s for s in list(b.manifest['Applications'].keys()) if "whatsapp" in s]
['group.net.whatsapp.WhatsApp.shared',
 'net.whatsapp.WhatsApp.ShareExtension',
 'group.net.whatsapp.WhatsAppSMB.shared',
 'net.whatsapp.WhatsApp.NotificationExtension',
 'net.whatsapp.WhatsApp.Intents',
 'net.whatsapp.WhatsApp.TodayExtension',
 'net.whatsapp.WhatsApp.IntentsUI',
 'group.net.whatsapp.WhatsApp.private',
 'net.whatsapp.WhatsApp.ServiceExtension',
 'net.whatsapp.WhatsApp']
```

### Restore All Files of Apps, Groups and Plugins Matching “_whatsapp_”
I had to use previous method to find the list of app IDs and see that “_whatsapp_” is a good word to match them.
Each app component has its own backup domain prefixed by `AppDomain`, `AppDomainGroup` or `AppDomainPlugin`.
So we'll iterate over all possibilities of fabricated domain names with `getFolderDecryptedCopy()`.
```python
for id in [s for s in list(b.manifest['Applications'].keys()) if "whatsapp" in s]:
    for prefix in ["AppDomain", "AppDomainGroup", "AppDomainPlugin"]:
        b.getFolderDecryptedCopy(includeDomains=prefix + '-' + id)
```
Other apps might have a less intuitive name. For example, Telegram can be matched by “_telegra_” (without ‘m’):
```python
for id in [s for s in list(b.manifest['Applications'].keys()) if "telegra" in s]:
    for prefix in ["AppDomain", "AppDomainGroup", "AppDomainPlugin"]:
        b.getFolderDecryptedCopy(includeDomains=prefix + '-' + id)
```

## Apple-native Python 3 Installation on Macs

Follow my guide at https://avi.alkalay.net/2019/12/macos-jupyter-data-science-no-anaconda.html

Basically use command `xcode-select --install` to get Python 3 installed and updated by Apple on your Mac.

## List of Domains

Domain | Contains
--- | ---
**AppDomain-...** | Backup of each installed app's files
**AppDomainGroup-...** | Backup of each installed app's files
**AppDomainPlugin-...** | Backup of each installed app's files
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
ed1f8fb5a948b40504c19580a458c384659a605e | WirelessDomain | Library/Databases/CellularUsage.db | Table `subscriber_info` apparently contains all SIM phone numbers ever inserted in the phone since about iOS 11 or 12. Data here is related to `Library/Preferences/com.apple.commcenter.plist`.
0d609c54856a9bb2d56729df1d68f2958a88426b | WirelessDomain | Library/Databases/DataUsage.sqlite | A rich database that apparently contains app WWAN usage through time. Chack tables `ZPROCESS` and `ZLIVEUSAGE`.
1570a95f5dc7f4cd6b54bc17c427eda95288b8fa | HomeDomain | Library/SpringBoard/LockVideo.mov | Video used as background on lock screen
. | HomeDomain | Library/Passes/Cards/* | Wallet passes and items
8d0167b67f664a3816b4c00115c2dfa6a8f81388 |WirelessDomain | Library/Preferences/com.apple.AppleBasebandManager.Statistics.plist | Apparently contains times of last boot and restores.
dafec408e48be2700704dd3e763014c39f6de6b3 | WirelessDomain | Library/Preferences/com.apple.AppleBasebandManager.plist
9329979c8298f9cd3fb110fa387570a8b957e912 | WirelessDomain | Library/Preferences/com.apple.CommCenter.counts.plist | Has `CellularBytesRecved` and `CellularBytesSent`
3dec38ca46c9e37ffebacf2611463eb47a65eb09 | WirelessDomain | Library/Preferences/com.apple.commcenter.audio.plist
7e5f642f6da5e2345c0893bdf944da9c53902756 | WirelessDomain | Library/Preferences/com.apple.commcenter.callservices.plist
bfecaa9c467e3acb085a5b312bd27bdd5cd7579a | WirelessDomain | Library/Preferences/com.apple.commcenter.plist | Cellular network informations and configurations, including all ever inserted SIM and eSIM cards, their phone numbers and nicknames as configured under Settings➔Celular. Data here is related to `Library/Databases/CellularUsage.db` 
160600e9c2e408c69e4193d325813a2a885bce2a | WirelessDomain | Library/Preferences/com.apple.ipTelephony.plist
. | HomeDomain | Library/Mobile Documents/iCloud~... | Apps documents on iCloud
. | HomeDomain | Library/Mobile Documents/com\~apple\~CloudDocs/... | Documents folder on iCloud
5a4935c78a5255723f707230a451d79c540d2741 | HomeDomain | Library/CallHistoryDB/CallHistory.storedata | Call History database with only the last 600 calls
31bb7ba8914766d4ba40d6dfb6113c8b614be442 | HomeDomain | Library/AddressBook/AddressBook.sqlitedb | User contacts and address book. Table `ABPerson` is the central one with facts about contact creation and modification, while `ABMultiValue*` tables contain contact details.
cd6702cea29fe89cf280a76794405adb17f9a0ee | HomeDomain | Library/AddressBook/AddressBookImages.sqlitedb | Contact photos
9db3e5a6f1672cc306cd785809811e79cc43a2f8 | HomeDomain | Library/AddressBook/backup/AddressBook.sqlitedb
2a87d5bcdb9753f1462dd1e929b17e6a971c5b01 | HomeDomain | Library/AddressBook/backup/AddressBookImages.sqlitedb
1a0e7afc19d307da602ccdcece51af33afe92c53 | HomeDomain | Library/Safari/History.db
. | MediaDomain | Library/SMS/Attachments/*
. | MediaDomain | Library/SMS/StickerCache/*
. | . | Library/Caches/locationd/consolidated.db | Apparently list of known iBeacons

