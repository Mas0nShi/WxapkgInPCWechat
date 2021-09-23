#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import os
import struct
import sys
from io import BytesIO

from Crypto.Cipher import AES
from loguru import logger
import jsbeautifier


class DepthTraversal:
    """
    按照深度遍历文件及文件夹，取出匹配格式的文件
    """

    def __init__(self, fmtList):
        """
        :param fmtList:文件列表 List - example [".exe", ".txt"]
        """
        self._files = []
        self._fmtList = fmtList

    def _deep_iterate_dir(self, _rootDir):
        """
        :param _rootDir: 根目录
        :return: None
        """
        import os
        for lists in os.listdir(_rootDir):
            _path = os.path.join(_rootDir, lists)
            if os.path.isdir(_path):
                self._deep_iterate_dir(_path)
            elif os.path.isfile(_path):
                ext = os.path.splitext(_path)[1]
                if ext in self._fmtList:
                    self._files.append(_path)

    def getMatchFiles(self, _rootDir):
        """
        :param _rootDir: 遍历根目录
        :return: 匹配文件列表
        """
        self._deep_iterate_dir(_rootDir)
        return self._files


class repairPkg:
    def __init__(self, rootPath):
        self.rootPath = rootPath
        self.sliceArr = []
        fileName = os.path.join(rootPath, "app-service.js")
        try:
            with open(fileName, "rb") as f:
                self.data = f.read()
        except FileNotFoundError:
            logger.error("FileNotFoundError: {}".format(fileName))
            return
        logger.debug("start fix wxapkg...")

    def exportFile(self):
        logger.debug("fix .js")

        class sliceFile(object):
            name = ""
            data = b""

        parseData = self.data.split(b"define(\"")
        self.wxmlData = parseData[0]

        print(jsbeautifier.beautify(self.wxmlData.decode()))
        for slice in parseData[1:]:
            arr = slice.split(b"\", ")
            sfile = sliceFile()
            sfile.name = arr[0].decode()
            sfile.data = arr[1][:arr[1].rfind(b"});")+1]
            self.sliceArr.append(sfile)

        for sfile in self.sliceArr:
            outFilePath = os.path.join(self.rootPath, sfile.name)
            dirPath = os.path.dirname(outFilePath)
            if not os.path.exists(dirPath):
                os.makedirs(dirPath)
            with open(outFilePath, "wb") as f:
                btCode = jsbeautifier.beautify(sfile.data.decode()).encode()  # 美化JavaScript代码
                f.write(btCode)
            logger.success("export file: {}".format(sfile.name))


def _AESDecrypt(src, key, iv):
    """
    AES-128-CBC
    :param src: bytes
    :param key: 16 bits
    :param iv: 16 bits
    :return: bytes
    """
    crypto = AES.new(key, AES.MODE_CBC, iv)
    decBuffer = crypto.decrypt(src)
    return decBuffer[0:(len(decBuffer) - decBuffer[-1])]


def decPCWxapkg(filePath, wxId):
    """
    对 WeChat PC端的小程序进行解密&解包

    :param filePath: wxapkg文件路径
    :param wxId: 小程序ID
    :return: None
    """
    with open(filePath, 'rb')as f:
        packBuffer = f.read()
        packlen = len(packBuffer)
        if packlen < 6:
            logger.error('file too small')
            exit(0)
        if not packBuffer.startswith('V1MMWX'.encode('utf-8')):
            logger.error('file format error')
            exit(0)
        pbkdf2Key = hashlib.pbkdf2_hmac('sha1', wxId.encode('utf-8'), 'saltiest'.encode('utf-8'), 1000, 32)
        iv = 'the iv: 16 bytes'
        if packlen > 1024 + 6:
            encPathData = packBuffer[6:1024 + 6]
            encAssetsData = packBuffer[1024 + 6:]
        else:
            encPathData = packBuffer[6:]
        decPathData = _AESDecrypt(encPathData, pbkdf2Key, iv.encode('utf-8'))
        if packlen > 1024 + 6:
            if len(wxId) < 2:
                xorKey = 0x66
            else:
                xorKey = wxId.encode('utf-8')[-2]
            assetslength = len(encAssetsData)
            fmt = '{}B'.format(assetslength)
            s = struct.unpack(fmt, encAssetsData)
            decAssetsData = struct.pack(fmt, *(a ^ xorKey for a in s))
            decfileData = decPathData + decAssetsData
            logger.success('Decryption is complete, ready to unpack')
        else:
            decfileData = decPathData
    return decfileData


def WxapkgUnPack(_rootPath, _fileName, _fileData):
    """
    wxapkg解包

    :param _rootPath: 根目录
    :param _fileName: wxapkg文件名称
    :param _fileData: wxapkg解密文件数据
    :return: fix?
    """

    class WxapkgFile(object):
        nameLen = 0
        name = b""
        offset = 0
        size = 0

    f = BytesIO(_fileData)
    # read header
    firstMark = struct.unpack('B', f.read(1))[0]
    logger.debug('FirstHeaderMark : {}'.format(firstMark))

    infoTable = struct.unpack('>L', f.read(4))[0]
    logger.debug('infoTable : {}'.format(infoTable))

    indexInfoLength = struct.unpack('>L', f.read(4))[0]
    logger.debug('indexInfoLength : {}'.format(indexInfoLength))

    bodyInfoLength = struct.unpack('>L', f.read(4))[0]
    logger.debug('bodyInfoLength : {}'.format(bodyInfoLength))

    lastMark = struct.unpack('B', f.read(1))[0]
    logger.debug('last header mark : {}'.format(lastMark))

    if firstMark != 0xBE or lastMark != 0xED:
        logger.error('It seems that this is not a valid file or the wxid you provided is wrong')
        f.close()
        exit(0)
    fileCount = struct.unpack('>L', f.read(4))[0]
    logger.debug('file Count : {}'.format(fileCount))

    # read index
    fileList = []
    for i in range(fileCount):
        data = WxapkgFile()
        data.nameLen = struct.unpack('>L', f.read(4))[0]
        data.name = f.read(data.nameLen)
        data.offset = struct.unpack('>L', f.read(4))[0]
        data.size = struct.unpack('>L', f.read(4))[0]
        logger.info('unpack : {} at Offset : {}'.format(str(data.name, encoding="utf-8"), data.offset))
        fileList.append(data)

    # save files
    nameList = []
    dirName = os.path.splitext(_fileName)[0]
    for st in fileList:
        outFileName = st.name.decode("utf-8")
        outFilePath = _rootPath + '\\' + dirName + outFileName
        nameList.append(outFileName)
        dirPath = os.path.dirname(outFilePath)
        if not os.path.exists(dirPath):
            os.makedirs(dirPath)
        w = open(outFilePath, 'wb')
        f.seek(st.offset)
        w.write(f.read(st.size))
        w.close()
        logger.success('save : {}'.format(outFileName))
    f.close()

    if "/app-service.js" in nameList:  # 是否存在 app-service.js
        return True
    else:
        return False


def decWithunPack(filePath, wxId):
    if os.path.isdir(filePath):
        logger.info("Detected the dir, traversed all the wxapkg under the dir")
        dt = DepthTraversal([".wxapkg"])
        pathList = dt.getMatchFiles(filePath)
        for file in pathList:
            rootPath = os.path.dirname(file)
            fileName = os.path.basename(file)
            logger.info("Working with files : {}".format(fileName))
            decPathData = decPCWxapkg(file, wxId)
            WxapkgUnPack(rootPath, fileName, decPathData)

            fix = repairPkg(os.path.join(rootPath, os.path.splitext(fileName)[0]))
            fix.exportFile()

    else:
        rootPath = os.path.dirname(filePath)
        fileName = os.path.basename(filePath)
        decPathData = decPCWxapkg(filePath, wxId)
        WxapkgUnPack(rootPath, fileName, decPathData)

        fix = repairPkg(os.path.join(rootPath,os.path.splitext(fileName)[0]))
        fix.exportFile()


def pwt(content, end="\n"):
    print("\033[1;37m {0} \033[0m".format(content), end=end)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        pyName = sys.argv[0]
        pwt("Usage : ")
        pwt("       python {0} [AbsFilePath] [wxId]".format(pyName))
        pwt("Example : ")
        pwt("       python {0} D:/WxapkgInPCWechat/apps/***.wxapkg wx****************".format(pyName))
        pwt("Tips : ")
        pwt("       AbsFilePath : The full path of the wxapkg file")
        pwt("              wxId : Applet ID")
        pwt("\n If you have any questions, please contact [ MasonShi@88.com ]\n")
        exit(0)
    path = sys.argv[1]
    wxid = sys.argv[2]
    decWithunPack(path, wxid)
