'''
Date: 2020-12-23 08:38:30
LastEditors: Rustle Karl
LastEditTime: 2020-12-24 20:40:19
'''
import os
import tempfile
import zlib
from queue import Queue
from threading import Thread
from typing import Union
from zipfile import ZipFile

import _lzma
import color
import py7zr
from rarfile import RarFile
from tqdm import tqdm

from .zipmd5 import ZipMd5

PACKAGE_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_DICT_FILE = os.path.join(PACKAGE_DIR, 'source.dat')
DEFAULT_DB_FILE = os.path.join(PACKAGE_DIR, 'zipmd5.db')


class ZipCracker(object):
    __password = None

    def __init__(self, pwd_file=DEFAULT_DICT_FILE, start=0,
                 database=DEFAULT_DB_FILE) -> None:

        with open(pwd_file, encoding='utf-8') as fp:
            passwords = fp.read().splitlines()

        self.queue = Queue()
        for password in tqdm(passwords[start:], desc='加载字典', ncols=81):
            self.queue.put(password)
        self.queue.put(None)

        self.proc = tqdm(total=self.queue.qsize(),
                         desc='暴力破解', ncols=81, mininterval=0.5)

        self.db = ZipMd5(database=database)

    def __extractall(self, target: Union[ZipFile, RarFile],
                     output: str, extractall=False) -> None:

        color.greenln('正在破解密码')
        while not self.__password and not self.queue.empty():
            pwd = self.queue.get()
            print(color.sblackf(pwd, light=True), end='\r')
            try:
                target.setpassword(pwd.encode('utf-8'))
                target.extractall(path=output)  # 中文乱码，随它吧
            except (RuntimeError, zlib.error):
                pass
            else:
                self.__password = pwd
                return
            finally:
                self.proc.update()

    def __extractall_7z(self, input_file: str, output: str):
        while not self.__password and not self.queue.empty():
            pwd = self.queue.get()
            try:
                with py7zr.SevenZipFile(input_file, password=pwd) as z:
                    z.extractall(path=output)
            except _lzma.LZMAError:
                pass
            except EOFError:
                self.queue.put(pwd)
            else:
                self.__password = pwd
                return
            finally:
                self.proc.update()

    def extractall(self, input_file: str, output: str, password: str):
        color.greenln('正在解压文件')

        ext = os.path.splitext(input_file)[-1]

        if ext == '.zip':
            ZipFile(input_file).extractall(
                output, pwd=password.encode('utf-8'))
        elif ext == '.rar':
            RarFile(input_file).extractall(
                output, pwd=password.encode('utf-8'))
        elif ext == '.7z':
            with py7zr.SevenZipFile(input_file, password=password) as z:
                z.extractall(path=output)
        else:
            raise NotImplementedError(ext)

        color.greenln('解压成功')
        return password

    def find_password(self, input_file: str, output: str = None,
                      max_threads=1, extractall=False) -> str:

        if not extractall:
            output = tempfile.gettempdir()
        elif output is None or not os.path.isdir(output):
            output = os.path.dirname(input_file)

        password, md5 = self.db.get_password(input_file)
        if password:
            self.proc.close()
            self.__password = password
            color.greenln('成功从数据库中获得密码')
            color.redln(self.__password)
            return self.extractall(input_file, output, password) if extractall else password

        color.redln('\nMD5:\n'+md5)

        max_threads = min(16, max_threads)  # 解压是 CPU 密集型，多了无用

        ext = os.path.splitext(input_file)[-1]
        if ext == '.zip':
            target = ZipFile(input_file)
        elif ext == '.rar':
            target = RarFile(input_file)
        elif ext == '.7z':
            max_threads = max(32, max_threads)
            target = input_file
        else:
            raise NotImplementedError(ext)

        # 多线程不如单线程快
        workers = [Thread(target=(self.__extractall_7z if
                                  ext == '.7z' else self.__extractall),
                          args=(target, output)) for _ in range(max_threads)]

        for worker in workers:
            worker.start()

        for worker in workers:
            worker.join()

        self.proc.close()

        if self.__password:
            color.greenln('成功从字典中获得密码')
            color.redln(self.__password)
            self.db.insert_password(md5, self.__password)
            return self.__password

        color.cyanln('未发现密码')


if __name__ == "__main__":
    input_file = r'H:\Temp\新建文件夹\受虐魅魔.zip'
    cracker = ZipCracker()
    cracker.find_password(input_file, max_threads=1, extractall=True)
