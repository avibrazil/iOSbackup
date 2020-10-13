import biplist
from importlib import import_module
import struct
import os
import sys
import textwrap
import pprint
import tempfile
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from Cryptodome.Cipher import AES
except:
    from Crypto.Cipher import AES # https://www.dlitz.net/software/pycrypto/


__version__ = '0.9.903'


class iOSbackup(object):
    """
    Class that reads and extracts files from a password-encrypted iOS backup created by
    iTunes on Mac and Windows. Compatible with iOS 13.

    You will need your backup password to decrypt the backup files, this is the password
    iTunes asks when it is configured to do encrypted backups. You should always prefer
    encrypted backups because they are more secure and include more files from your
    device. Non-encrypted backups do not backup files as Health app database
    and other preciosities.
    
    Common Usage
    ------------
    iOSbackup.getDeviceList()
    
    b=iOSbackup(udid="07349330-000327638962802E", derivedkey="dd61467e94c5dbdff780ddd9abdefb1b0e33b6426875a3e397cb47f351524")
    
    files=b.getBackupFilesList()
    
    b.getFileDecryptedCopy(relativePath="Library/Databases/CellularUsage.db")
    
    
    Attributes
    ----------
    backupRoot : str
        Full path of folder that contains device backups. On macOS this is ~/Library/Application Support/MobileSync/Backup
    udid : str
        The UDID of current device backup being handled.
    manifest : dict
        Device backup information as retrieved from Manifest.plist file
    manifestDB : str
        Full path of the usable decrypted copy of backup's Manifest.db file.
    platformFoldersHint : dict
        List of folders per platform used by iTunes to store device backups.
    decryptionKey : bytes
        The master backup decryption key derived directly from user's backup password.


    User Methods
    ------------
    iOSbackup()
        Constructor that delivers an initialized and usable instance of the class
    getHintedBackupRoot()
        Get full path of best-match folder name containing iOS backups, based on your platform.
    setBackupRoot()
        Set it explicitly if folder is different from what is known by platformFoldersHint
    getDeviceList()
        Returns list of devices found under backupRoot. Can be used as a static method.
    getDeviceBasicInfo()
        Static method that returns a dict of basic info about a device and its backup
    setDevice()
        Set the device by its UDID
    getBackupFilesList()
        Returns a dict with all device backup files catalogued in its Manifest.db
    getFileDecryptedCopy()
        Returns a dict with filename of a decrypted copy of certain file along with some file information
    getManifestDB()
        Returns full path name of a decrypted copy of Manifest.db
    getDecryptionKey()
        Returns decryptionKey as hex bytes


    Internal Methods
    ----------------
    deriveKeyFromPassword()
        Calculates, stores and return decryptionKey from user's clear text backup password
    loadKeys()
        Loads various encrypted decryption keys from Manifest.plist
    unlockKeys()
        Use decryptionKey to decrypt keys loaded by loadKeys()
        
    
    
    
    
    The process of accessing an encrypted iOS backup (encapsulated and made
    easier by this class) goes like this:
    
    1. Load encrypted keys (loadKeys()) from Manifest.plist file found on device's backup folder.
    2. Use Manifest.plist's parameters to derive a master decryption key (deriveKeyFromPassword()) from user's backup password (lengthy process), or use the provided derivedkey.
    3. Decrypt Manifest.plist's keys with derivedkey (unlockKeys())
    4. Use Manifest.plist decrypted keys to decrypt Manifest.db and save it unencrypted as a temporary file (getManifestDB()).
    5. Use decrypted version of Manifest.db SQLite database as a catalog to find and decrypt all other files of the backup.
    """
    
    # Most crypto code here from https://stackoverflow.com/a/13793043/367824
    
    platformFoldersHint={
        'darwin': '~/Library/Application Support/MobileSync/Backup',
        'win32': r'%HOME%\Apple Computer\MobileSync\Backup'
    }
    
    WRAP_PASSCODE = 2
    
    CLASSKEY_TAGS = [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"]  #UUID

    def __del__(self):
        os.remove(self.manifestDB)
    
    def __init__(self, udid, cleartextpassword=None, derivedkey=None, backuproot=None):
        """Constructor that delivers an initialized and usable instance of the class.

        Parameters
        ----------
        backuproot : str, optional
            Full path of folder that contains device backups. Uses platformFoldersHint if omitted.
        udid : str
            The UDID (and folder name) of device that you want to access its backup.
        cleartextpassword : str, optional
            User's backup password as provided to iTunes on backup creation time.
        derivedkey : str, optional
            The master backup decryption key derived directly from user's backup password.
            Use it instead of cleartextpassword to save time and to not reveal your password.
        """
        self.setBackupRoot(backuproot)
        self.udid = udid
        self.date = None # modification time of Manifest.plist is backup time, set by loadKeys()
        self.decryptionKey = None
        self.attrs = {}
        self.uuid = None
        self.wrap = None
        self.classKeys = {}
        self.manifest = None
        self.manifestDB = None


        self.loadKeys()
        
        if derivedkey:
            if type(derivedkey)==str:
                self.decryptionKey=bytes.fromhex(derivedkey)
            else:
                self.decryptionKey=derivedkey

        if cleartextpassword:
            self.deriveKeyFromPassword(cleartextpassword.encode('utf-8'))
        
        # Need password set before trying to unlock keys...
        self.unlockKeys()
        
        self.getManifestDB()



    def __repr__(self):
        """Prints a lot of information about an opened backup"""

        template=textwrap.dedent("""\
            backup root folder: {backupRoot}
            device ID: {udid}
            date: {date}
            uuid: {uuid}
            device name: {name}
            device type: {type}
            iOS version: {ios}
            serial: {serial}
            manifest[IsEncrypted]: {IsEncrypted}
            manifest[WasPasscodeSet]: {PasscodeSet}
            decrypted manifest DB: {manifestDB}
            decryptionKey: {decryptionKey}
            manifest[ManifestKey]: {ManifestKey}
            attr: {attrs}
            classKeys: {classKeys}
            wrap: {wrap}
            manifest[Applications]: {Applications}""")
        
        return template.format(
            backupRoot=self.backupRoot,
            udid=self.udid,
            date=self.date,
            decryptionKey=self.getDecryptionKey(),
            uuid=self.uuid.hex(),
            attrs=pprint.pformat(self.attrs, indent=4),
            wrap=self.wrap,
            classKeys=pprint.pformat(self.classKeys, indent=4),
            IsEncrypted=self.manifest['IsEncrypted'],
            PasscodeSet=self.manifest['WasPasscodeSet'],
            ManifestKey=self.manifest['ManifestKey'].hex(),
            Applications=pprint.pformat(self.manifest['Applications'], indent=4),
            manifestDB=self.manifestDB,
            name=self.manifest['Lockdown']['DeviceName'],
            ios=self.manifest['Lockdown']['ProductVersion'],
            serial=self.manifest['Lockdown']['SerialNumber'],
            type=self.manifest['Lockdown']['ProductType']
        )



    def getDecryptionKey(self) -> str:
        """Decryption key is tha master blob to decrypt everything in the iOS backup.
        It is calculated by deriveKeyFromPassword() from the clear text iOS backup password.
        """
        
        return self.decryptionKey.hex()


    def getHintedBackupRoot() -> str:
        """Get full path of best-match folder name containing iOS backups, based on your platform."""
        
        for plat in iOSbackup.platformFoldersHint.keys():
            if sys.platform.startswith(plat):
                return os.path.expanduser(os.path.expandvars(iOSbackup.platformFoldersHint[plat]))
        return None


    def setBackupRoot(self, path=None):
        """Set it explicitly if folder is different from what is known by platformFoldersHint

        Parameters
        ----------
        path : str, optional
            Full path of folder that contains device backups. Uses platformFoldersHint if omitted.
        """

        if path:
            self.backupRoot=os.path.expanduser(os.path.expandvars(path))
        else:
            self.backupRoot=iOSbackup.getHintedBackupRoot()


    def getDeviceBasicInfo(udid=None, backuproot=None):
        """Static method that returns a dict of basic info about a device and its backup.
        
        Parameters
        ----------
        backuproot : str, optional
            Full path of folder that contains device backups. Uses platformFoldersHint if omitted.
        """
        info=None
        root=None
        
        if backuproot:
             root=os.path.expanduser(backuproot)
        else:
            root=iOSbackup.getHintedBackupRoot()
            
        if udid and root:
            manifestFile = os.path.join(root,udid,'Manifest.plist')
            with open(manifestFile, 'rb') as infile:
                manifest = biplist.readPlist(infile)
                info={
                    "udid": udid,
                    "name": manifest['Lockdown']['DeviceName'],
                    "ios": manifest['Lockdown']['ProductVersion'],
                    "serial": manifest['Lockdown']['SerialNumber'],
                    "type": manifest['Lockdown']['ProductType'],
                    "encrypted": manifest['IsEncrypted'],
                    "passcodeSet": manifest['WasPasscodeSet'],
                    "date": iOSbackup.convertTime(os.path.getmtime(manifestFile), since2001=False)
                }
        else:
            raise Exception("Need valid backup root folder path and a device UDID.")
        
        return info


    
    def getDeviceList(self, backuproot=None):
        """Returns list of devices found under backuproot.
        
        Parameters
        ----------
        backuproot : str, optional
            Full path of folder that contains device backups. Uses platformFoldersHint if omitted.
        """ 

        list=[]
        
        if backuproot:
            self.setBackupRoot(backuproot)
        elif not self.backupRoot:
            # Set defaults
            self.setBackupRoot()

        if self.backupRoot:
            (_, dirnames, _)=next(os.walk(self.backupRoot))
        
            for i in dirnames:
                list.append(iOSbackup.getDeviceBasicInfo(udid=i, backuproot=self.backupRoot))
            
            return list
        else:
            raise Exception("Need valid backup root folder path passed through `backuproot`.")



    
    def getDeviceList(backuproot=None):
        """Returns list of devices found under backuproot. Static method.
        
        Parameters
        ----------
        backuproot : str, optional
            Full path of folder that contains device backups. Uses platformFoldersHint if omitted.
        """
        
        list=[]
        root=None
        
        if backuproot:
            root=os.path.expanduser(backuproot)
        else:
            root=iOSbackup.getHintedBackupRoot()

        if root:
            (_, dirnames, _)=next(os.walk(root))
        
            for i in dirnames:
                list.append(iOSbackup.getDeviceBasicInfo(udid=i, backuproot=root))

            return list
        else:
            raise Exception("Need valid backup root folder path passed through `backuproot`.")



    def setDevice(self,udid=None):
        """Set the device by its UDID"""
        
        self.udid=udid
        
        
        
    def getBackupFilesList(self):
        """Returns a dict with all device backup files catalogued in its Manifest.db"""
        
        if not self.manifestDB:
            raise Exception("Object not yet innitialized or can't find decrypted files catalog (Manifest.db)")

        catalog = sqlite3.connect(self.manifestDB)
        catalog.row_factory=sqlite3.Row
        
        backupFiles = catalog.cursor().execute(f"SELECT * FROM Files ORDER BY domain,relativePath").fetchall()
        
        list=[]
        for f in backupFiles:
            info={
                "name": f['relativePath'],
                "backupFile": f['fileID'],
                "domain": f['domain'],
                **f
            }
            list.append(info)

        return list


    def getFolderDecryptedCopy(self, relativePath=None, targetFolder=None, temporary=False, includeDomains=None, excludeDomains=None, includeFiles=None, excludeFiles=None):
        """Recreates under targetFolder an entire folder (relativePath) found into an iOS backup.
        
        Parameters
        ----------
        relativePath : str
            Semi full path name of a backup file. Something like 'Media/PhotoData/Metadata'
        targetFolder : str, optional
            Folder where to store decrypted files, creates the folder tree under current folder if omitted.
        temporary : str, optional
            Creates a temporary file (using tempfile module) in a temporary folder. Use targetFolder if omitted.
        includeDomains : str, list, optional
            Retrieve files only from this single or list of iOS backup domains.
        excludeDomains : str, list, optional
            Retrieve files from all but this single or list of iOS backup domains.
        includeFiles : str, list, optional
            SQL friendly file name matches. For example "%JPG" will retrieve only files ending with JPG. Pass a list of filters to be more effective.
        excludeFiles : str, list, optional
            SQL friendly file name matches to exclude. For example "%MOV" will retrieve all but files ending with MOV. Pass a list of filters to be more effective.
        
        Returns
        -------
        List of dicts with info about all files retrieved.
        """
        
        if not self.manifestDB:
            raise Exception("Object not yet innitialized or can't find decrypted files catalog (Manifest.db)")
            
        if not relativePath:
            relativePath=''
            if not includeDomains:
                raise Exception("relativePath and includeDomains cannot be empty at the same time")
        
        if temporary:
            targetRootFolder=tempfile.TemporaryDirectory(suffix=f"---{fileName}", dir=targetFolder)
            targetRootFolder=targetRootFolder.name
        else:
            if targetFolder:
                targetRootFolder=targetFolder
            else:
                targetRootFolder='.'
        
        additionalFilters=[]
        
        if includeDomains:
            if type(includeDomains)==list:
                additionalFilters.append('domain IN ({})'.format(','.join("'" + item + "'" for item in includeDomains)))
            else:
                additionalFilters.append('''domain = '{}' '''.format(includeDomains))


        if excludeDomains:
            if type(excludeDomains)==list:
                additionalFilters.append('domain NOT IN ({})'.format(','.join("'" + item + "'" for item in excludeDomains)))
            else:
                additionalFilters.append('''domain != '{}' '''.format(excludeDomains))

                
                
                
                
        if includeFiles:
            ifiles=[]
            if type(includeFiles)==list:
                for i in includeFiles:
                    ifiles.append(f"relativePath LIKE '{i}'")
                    
                ifiles='(' + ' OR '.join(ifiles) + ')'
                additionalFilters.append(ifiles)
            else:
                additionalFilters.append(f"relativePath LIKE '{includeFiles}'")


        if excludeFiles:
            ifiles=[]
            if type(excludeFiles)==list:
                for i in excludeFiles:
                    ifiles.append(f"relativePath NOT LIKE '{i}'")
                    
                ifiles='(' + ' AND '.join(ifiles) + ')'
                additionalFilters.append(ifiles)
            else:
                additionalFilters.append(f"relativePath NOT LIKE '{excludeFiles}'")


                
                
                
                
        if len(additionalFilters)>0:
            additionalFilters.insert(0,'') # so we dont brake SQL due to lack of 'AND'
        
        catalog = sqlite3.connect(self.manifestDB)
        catalog.row_factory=sqlite3.Row
        
        query="SELECT * FROM Files WHERE relativePath LIKE '{relativePath}%' {additionalFilters} ORDER BY domain, relativePath".format(
            relativePath=relativePath,
            additionalFilters=' AND '.join(additionalFilters)
        )
                
        backupFiles = catalog.cursor().execute(query).fetchall()
                
        fileList=[]
        for f in backupFiles:
            info={}
            (info,decrypted)=self.getFileDecryptedData(fileNameHash=f['fileID'],manifestData=f['file'])
            
            physicalTarget=os.path.join(targetRootFolder,f['domain'],f['relativePath'])
            
            if info['isFolder']:
                Path(physicalTarget).mkdir(parents=True, exist_ok=True)
            else:
                Path(os.path.dirname(physicalTarget)).mkdir(parents=True, exist_ok=True)
                with open(physicalTarget,'wb',info['mode']) as output:
                    output.write(decrypted)

            mtime=time.mktime(info['lastModified'].astimezone(tz=None).timetuple())
            os.utime(physicalTarget,(mtime, mtime))

            info['originalFilePath']=relativePath
            info['decryptedFilePath']=physicalTarget
            info['domain']=f['domain']
            info['backupFile']=f['fileID']

            fileList.append(info)
            
        catalog.close()
        return fileList


    
    def getFileManifestDBEntry(self, fileNameHash=None, relativePath=None):
        """Get the Manifest DB entry for a file either from its file name hash or relative file name.
        File name hash is more precise because its unique, while the relative file name may appear under multiple backup domains.
        
        Parameters
        ----------
        relativePath : str
            Semi full path name of a backup file. Something like 'Media/PhotoData/Metadata'
        fileNameHash : str
            Hashed filename as can be seen under iOS backup folder.
        
        Returns
        -------
        A dict with Manifest info about the file along with the file manifest.

        """
        if fileNameHash==None and relativePath==None:
            raise Exception(f"Either fileNameHash or relativePath must be provided")
            
        if not self.manifestDB:
            raise Exception("Object not yet innitialized or can't find decrypted files catalog (Manifest.db)")
        
        catalog = sqlite3.connect(self.manifestDB)
        catalog.row_factory=sqlite3.Row

        if relativePath:
            backupFile = catalog.cursor().execute(f"SELECT * FROM Files WHERE relativePath='{relativePath}' ORDER BY domain LIMIT 1").fetchone()
        else:
            backupFile = catalog.cursor().execute(f"SELECT * FROM Files WHERE fileID='{fileNameHash}' ORDER BY domain LIMIT 1").fetchone()
        
        catalog.close()
        
        if backupFile:
            payload=dict(backupFile)
            payload['manifest']=biplist.readPlistFromString(payload['file'])
        else:
            raise(FileNotFoundError(f"Can't find file «{relativePath}» on this backup"))

        return payload
        

    def getFileDecryptedData(self, fileNameHash, manifestData):
        """Given a backup file hash along with its manifest data (as returned by getFileManifestDBEntry()), returns a
        dict of file metadata and the decrypted content of the file. This is the memory-only version of getFileDecryptedCopy().
        """
        if type(manifestData)==dict:
            # Assuming this is biplist-processed plist file already converted into a dict
            manifest=manifestData
        elif type(manifestData)==bytes:
            # Interpret data stream and convert into a dict
            manifest = biplist.readPlistFromString(manifestData)

        fileData=manifest['$objects'][manifest['$top']['root'].integer]
                
        if 'EncryptionKey' in fileData:
            folder=False
            
            encryptionKey=manifest['$objects'][fileData['EncryptionKey'].integer]['NS.data'][4:]


            # {BACKUP_ROOT}/{UDID}/ae/ae2c3d4e5f6...
            with open(os.path.join(self.backupRoot, self.udid, fileNameHash[:2], fileNameHash), 'rb') as infile:
                dataEncrypted = infile.read()

            key = self.unwrapKeyForClass(fileData['ProtectionClass'], encryptionKey)

            # See https://github.com/avibrazil/iOSbackup/issues/1
            dataDecrypted = iOSbackup.AESdecryptCBC(dataEncrypted, key, padding=True)
        else:
            dataDecrypted=None
            folder=True
        
        info={
            "size": fileData['Size'],
            "created": iOSbackup.convertTime(fileData['Birth'], since2001=False),
            "lastModified": iOSbackup.convertTime(fileData['LastModified'], since2001=False),
            "lastStatusChange": iOSbackup.convertTime(fileData['LastStatusChange'], since2001=False),
            "mode": fileData['Mode'],
            "isFolder": folder,
            "userID": fileData['UserID'],
            "inode": fileData['InodeNumber'],
            "completeManifest": manifest
        }

        return (info, dataDecrypted)


        
    
    def getFileDecryptedCopy(self, relativePath, targetName=None, targetFolder=None, temporary=False):
        """Returns a dict with filename of a decrypted copy of certain file along with some file information
        
        Parameters
        ----------
        relativePath : str
            Semi full path name of a backup file. Something like 'Library/CallHistoryDB/CallHistory.storedata'
        targetName : str, optional
            File name on targetFolder where to save decrypted data. Uses something like 'HomeDomain~Library--CallHistoryDB--CallHistory.storedata' if omitted.
        targetFolder : str, optional
            Folder where to store decrypted file, saves on current folder if omitted.
        temporary : str, optional
            Creates a temporary file (using tempfile module) in a temporary folder. Use targetFolder if omitted.
        
        Returns
        -------
        A dict of metadata about the file.
        """

        if not relativePath:
            return None

        backupFile=self.getFileManifestDBEntry(relativePath=relativePath)
        
        (info,dataDecrypted)=self.getFileDecryptedData(backupFile['fileID'],backupFile['manifest'])
                        
        if targetName:
            fileName=targetName
        else:
            fileName='{domain}~{modifiedPath}'.format(domain=backupFile['domain'],modifiedPath=relativePath.replace('/','--'))

        if temporary:
            targetFileName=tempfile.NamedTemporaryFile(suffix=f"---{fileName}", dir=targetFolder, delete=True)
            targetFileName=targetFileName.name
        else:
            if targetFolder:
                targetFileName=os.path.join(targetFolder,fileName)
            else:
                targetFileName=fileName

        with open(targetFileName,'wb') as output:
            output.write(dataDecrypted)

        # Set file modification date and localtime time as per device's
        mtime=time.mktime(info['lastModified'].astimezone(tz=None).timetuple())
        os.utime(targetFileName,(mtime, mtime))

        # Add more information to the returned info dict
        info['originalFilePath']=relativePath
        info['decryptedFilePath']=targetFileName
        info['domain']=backupFile['domain']
        info['backupFile']=backupFile['fileID']

        return info
            

    def convertTime(timeToConvert, since2001=True):
        """Smart and static method that converts time values.
        If timeToConvert is an integer, it is considered as UTC Unix time and will be converted to a Python datetime object with timezone set on UTC.
        If timeToConvert is a Python datetime object, converts to UTC Unix time integer.
        If since2001 is True (default), integer values start at 2001-01-01 00:00:00 UTC, not 1970-01-01 00:00:00 UTC (as standard Unix time).
        """
        
        apple2001reference=datetime(2001, 1, 1, tzinfo=timezone.utc)
        
        if type(timeToConvert)==int or type(timeToConvert)==float:
            # convert from UTC timestamp to datetime.datetime python object on UTC timezone
            if since2001:
                return datetime.fromtimestamp(timeToConvert + apple2001reference.timestamp(), timezone.utc)
            else:
                return datetime.fromtimestamp(timeToConvert, timezone.utc)
            
        
        if isinstance(timeToConvert, datetime):
            # convert from timezone-aware datetime Python object to UTC UNIX timestamp
            if since2001:
                return (timeToConvert - apple2001reference).total_seconds()
            else:
                return timeToConvert.timestamp()


    
    def getManifestDB(self):
        """Returns full path name of a decrypted copy of Manifest.db. Used internally."""
        
        with open(os.path.join(self.backupRoot,self.udid,'Manifest.db'), 'rb') as db:
            encrypted_db = db.read()

        manifest_class = struct.unpack('<l', self.manifest['ManifestKey'][:4])[0]
        manifest_key   = self.manifest['ManifestKey'][4:]        
        
        key = self.unwrapKeyForClass(manifest_class, manifest_key)
        
        decrypted_data = iOSbackup.AESdecryptCBC(encrypted_db, key)
        
#         print(len(decrypted_data))
        
        file=tempfile.NamedTemporaryFile(suffix="--Manifest.db", delete=False)
        self.manifestDB=file.name
        file.write(decrypted_data)
        file.close()
        
        
    
    def loadKeys(self):
        manifestFile = os.path.join(self.backupRoot,self.udid,'Manifest.plist')
        
        self.date=iOSbackup.convertTime(os.path.getmtime(manifestFile), since2001=False)
        
        with open(manifestFile, 'rb') as infile:
            self.manifest = biplist.readPlist(infile)

        backupKeyBag=self.manifest['BackupKeyBag']
        currentClassKey = None

        for tag, data in iOSbackup.loopTLVBlocks(backupKeyBag):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == b"TYPE":
                self.type = data
                if self.type > 3:
                    print("FAIL: keybag type > 3 : %d" % self.type)
            elif tag == b"UUID" and self.uuid is None:
                self.uuid = data
            elif tag == b"WRAP" and self.wrap is None:
                self.wrap = data
            elif tag == b"UUID":
                if currentClassKey:
                    self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
                currentClassKey = {b"UUID": data}
            elif tag in self.CLASSKEY_TAGS:
                currentClassKey[tag] = data
            else:
                self.attrs[tag] = data
        if currentClassKey:
            self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
        
    

    def deriveKeyFromPassword(self,cleanpassword=None):
        # Try to use fastpbkdf2.pbkdf2_hmac().
        # Fallback to Pythons default hashlib.pbkdf2_hmac() if not found.
        
        try:
            hlib = import_module('fastpbkdf2')
        except:
            hlib = import_module('hashlib')
        
        
        temp = hlib.pbkdf2_hmac('sha256', cleanpassword,
            self.attrs[b"DPSL"],
            self.attrs[b"DPIC"], 32)
        
        self.decryptionKey = hlib.pbkdf2_hmac('sha1', temp,
            self.attrs[b"SALT"],
            self.attrs[b"ITER"], 32)
        
        return self.decryptionKey

    

    def unlockKeys(self):
        for classkey in self.classKeys.values():
            if b"WPKY" not in classkey:
                continue
                
            if classkey[b"WRAP"] & self.WRAP_PASSCODE:
                k = iOSbackup.AESUnwrap(self.decryptionKey,classkey[b"WPKY"])
                if not k:
                    return False
                classkey[b"KEY"] = k
                
        return True



    def unwrapKeyForClass(self, protection_class, persistent_key):
        if len(persistent_key) != 0x28:
            raise Exception("Invalid key length")

#         print(f"class: {protection_class}, key: {persistent_key}")
        ck = self.classKeys[protection_class][b"KEY"]
        return iOSbackup.AESUnwrap(ck, persistent_key)


           
    def unpack64bit(s):
        return struct.unpack(">Q",s)[0]



    def pack64bit(s):
        return struct.pack(">Q",s)



    def AESUnwrap(kek=None, wrapped=None):
        key=kek
        
        C = []
        for i in range(len(wrapped)//8):
            C.append(iOSbackup.unpack64bit(wrapped[i*8:i*8+8]))
        n = len(C) - 1
        R = [0] * (n+1)
        A = C[0]

        for i in range(1,n+1):
            R[i] = C[i]

        for j in reversed(range(0,6)):
            for i in reversed(range(1,n+1)):
                todec = iOSbackup.pack64bit(A ^ (n*j+i))
                todec += iOSbackup.pack64bit(R[i])
                B = AES.new(key, AES.MODE_ECB).decrypt(todec)
                A = iOSbackup.unpack64bit(B[:8])
                R[i] = iOSbackup.unpack64bit(B[8:])

        if A != 0xa6a6a6a6a6a6a6a6:
            return None
        res = b"".join(map(iOSbackup.pack64bit, R[1:]))
        return res




    def removePadding(blocksize, s):
        'Remove RFC1423 padding from string.'
        
        n = s[-1] # last byte contains number of padding bytes
        
        if n > blocksize or n > len(s):
            raise Exception('invalid padding')
            
        return s[:-n]



    def AESdecryptCBC(data, key, iv=b'\x00'*16, padding=False):
        todec = data
        
        if len(data) % 16:
#             print("AESdecryptCBC: data length not /16, truncating")
            todec = data[0:(len(data)/16) * 16]
    
        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(todec)
        
        if padding:
            return iOSbackup.removePadding(16, dec)
            
        return dec
        


    def loopTLVBlocks(blob):
        i = 0
        while i + 8 <= len(blob):
            tag = blob[i:i+4]
            length = struct.unpack(">L",blob[i+4:i+8])[0]
            data = blob[i+8:i+8+length]
            yield (tag,data)
            i += 8 + length
    
