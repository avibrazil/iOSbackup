import biplist
import fastpbkdf2
import struct
import os
import sys
import textwrap
import pprint
import tempfile
import sqlite3
import Crypto.Cipher.AES # https://www.dlitz.net/software/pycrypto/


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
            uuid: {uuid}
            device name: {name}
            device type: {type}
            iOS version: {ios}
            serial: {serial}
            manifest[IsEncrypted]: {IsEncrypted}
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
            decryptionKey=self.getDecryptionKey(),
            uuid=self.uuid.hex(),
            attrs=pprint.pformat(self.attrs, indent=4),
            wrap=self.wrap,
            classKeys=pprint.pformat(self.classKeys, indent=4),
            IsEncrypted=self.manifest['IsEncrypted'],
            ManifestKey=self.manifest['ManifestKey'].hex(),
            Applications=pprint.pformat(self.manifest['Applications'], indent=4),
            manifestDB=self.manifestDB,
            name=self.manifest['Lockdown']['DeviceName'],
            ios=self.manifest['Lockdown']['ProductVersion'],
            serial=self.manifest['Lockdown']['SerialNumber'],
            type=self.manifest['Lockdown']['ProductType']
        )



    def getDecryptionKey(self) -> str:
        return self.decryptionKey.hex()



    def getHintedBackupRoot() -> str:
        """Get full path of best-match folder name containing iOS backups, based on your platform."""
        
        for plat in iOSbackup.platformFoldersHint.keys():
            if sys.platform.startswith(plat):
                return os.path.expanduser(iOSbackup.platformFoldersHint[plat])
        return None
		

    def setBackupRoot(self, path=None):
        """Set it explicitly if folder is different from what is known by platformFoldersHint

        Parameters
        ----------
        path : str, optional
            Full path of folder that contains device backups. Uses platformFoldersHint if omitted.
        """
    	
        if path:
            self.backupRoot=os.path.expanduser(path)
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
                    "encrypted": manifest['IsEncrypted']
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
            raise Exception("Need valid backup root folder path.")



    
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
            raise Exception("Need valid backup root folder path.")



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
                "domain": f['domain']
            }
            list.append(info)

        return list


    
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
            Creates a temporary file (using tempfile module) in a temporary folder. Use targetFolder if not omitted.
        """
		
        if not self.manifestDB:
            raise Exception("Object not yet innitialized or can't find decrypted files catalog (Manifest.db)")
            
        if not relativePath:
            return None
        
        catalog = sqlite3.connect(self.manifestDB)
        catalog.row_factory=sqlite3.Row
        
        backupFile = catalog.cursor().execute(f"SELECT * FROM Files WHERE relativePath='{relativePath}' ORDER BY domain LIMIT 1").fetchone()
        
        if backupFile:
            manifest = biplist.readPlistFromString(backupFile['file'])

            fileData=manifest['$objects'][manifest['$top']['root'].integer]
            encryptionKey=manifest['$objects'][fileData['EncryptionKey'].integer]['NS.data'][4:]
            
            
            # BACKUP_ROOT/UDID/ae/ae2c3d4e5f6...
            with open(os.path.join(self.backupRoot,self.udid,backupFile['fileID'][:2], backupFile['fileID']), 'rb') as infile:
                dataEncrypted = infile.read()
                
            key = self.unwrapKeyForClass(fileData['ProtectionClass'], encryptionKey)
            # truncate to actual length, as encryption may introduce padding
            dataDecrypted = iOSbackup.AESdecryptCBC(dataEncrypted, key)[:fileData['Size']]
            
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
            
            info={
                "decryptedFilePath": targetFileName,
                "domain": backupFile['domain'],
                "originalFilePath": relativePath,
                "backupFile": backupFile['fileID'],
                "size": fileData['Size']
            }
            
            return info
        else:
            raise Exception(f"Can't find file {relativePath} on this backup")
            

                
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
        temp = fastpbkdf2.pbkdf2_hmac('sha256', cleanpassword,
            self.attrs[b"DPSL"],
            self.attrs[b"DPIC"], 32)
        
        self.decryptionKey = fastpbkdf2.pbkdf2_hmac('sha1', temp,
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
                B = Crypto.Cipher.AES.new(key).decrypt(todec)
                A = iOSbackup.unpack64bit(B[:8])
                R[i] = iOSbackup.unpack64bit(B[8:])

        if A != 0xa6a6a6a6a6a6a6a6:
            return None
        res = b"".join(map(iOSbackup.pack64bit, R[1:]))
        return res



    def AESdecryptCBC(data, key, iv="\x00"*16, padding=False):
        todec = None
        
        if len(data) % 16:
#             print("AESdecryptCBC: data length not /16, truncating")
            todec=data[0:(len(data)/16) * 16]
        else:
            todec=data
    
        dec = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(todec)
        
        if padding:
            return removePadding(16, dec)
        return dec
        


    def loopTLVBlocks(blob):
        i = 0
        while i + 8 <= len(blob):
            tag = blob[i:i+4]
            length = struct.unpack(">L",blob[i+4:i+8])[0]
            data = blob[i+8:i+8+length]
            yield (tag,data)
            i += 8 + length
    
