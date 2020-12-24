'''
Date: 2020-12-23 08:38:30
LastEditors: Rustle Karl
LastEditTime: 2020-12-24 13:41:56
'''
import os
import tempfile
from queue import Queue
from threading import Thread
from typing import Union
from zipfile import ZipFile

import _lzma
import color
import py7zr
from rarfile import RarFile
from tqdm import tqdm

from zipmd5 import ZipMd5


class ZipCracker(object):
    __password = None

    def __init__(self, pwd_file='storage/source.dat', start=0) -> None:

        with open(pwd_file, encoding='utf-8') as fp:
            passwords = fp.read().splitlines()

        self.queue = Queue()
        for password in tqdm(passwords[start:], desc='读取字典'):
            self.queue.put(password)
        self.queue.put(None)

        self.proc = tqdm(total=self.queue.qsize(), desc='暴力破解')

        self.db = ZipMd5()

    def __extractall(self, target: Union[ZipFile, RarFile],
                     output: str = None) -> None:
        while not self.__password and not self.queue.empty():
            pwd = self.queue.get()
            self.proc.update()
            try:
                target.extractall(path=output, pwd=pwd.encode('utf-8'))
                self.__password = pwd
                return
            except Exception:
                pass
        return

    def __extractall_7z(self, input_file: str, output: str = None):
        while not self.__password and not self.queue.empty():
            pwd = self.queue.get()
            try:
                with py7zr.SevenZipFile(input_file, password=pwd) as z:
                    z.extractall(path=output)
                self.__password = pwd
                return
            except _lzma.LZMAError:
                pass
            finally:
                self.proc.update()

    def find_password(self, input_file: str, output: str = None,
                      max_threads=1, extractall=False) -> str:

        password, md5 = self.db.get_password(input_file)
        if password:
            self.__password = password
            color.redln('\n' + self.__password)
            return ''

        if not extractall:
            output = tempfile.gettempdir()
        elif output is None or not os.path.isdir(output):
            output = os.path.dirname(input_file)

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

        if self.__password:
            color.redln('\n' + self.__password)
            self.db.insert_password(md5, self.__password)
            return self.__password

        color.cyanln('not found')


if __name__ == "__main__":
    keeper = ZipCracker('storage/source.dat', start=32000)
    input_file = 'storage/zip/flow.zip'
    keeper.find_password(input_file)
