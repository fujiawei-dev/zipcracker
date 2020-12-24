'''
Date: 2020-12-23 08:38:30
LastEditors: Rustle Karl
LastEditTime: 2020-12-24 16:31:44
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

from zipmd5 import ZipMd5


class ZipCracker(object):
    __password = None

    def __init__(self, pwd_file='storage/source.dat', start=0) -> None:

        with open(pwd_file, encoding='utf-8') as fp:
            passwords = fp.read().splitlines()

        self.queue = Queue()
        for password in tqdm(passwords[start:], desc='加载字典', ncols=81):
            self.queue.put(password)
        self.queue.put(None)

        self.proc = tqdm(total=self.queue.qsize(),
                         desc='暴力破解', ncols=81, mininterval=0.5)

        self.db = ZipMd5()

    def __extractall(self, target: Union[ZipFile, RarFile],
                     output: str, extractall=False) -> None:
        while not self.__password and not self.queue.empty():
            pwd = self.queue.get()
            try:
                target.setpassword(pwd.encode('utf-8'))
                if extractall:
                    target.extractall(path=output)
                elif hasattr(target, 'testzip'):
                    target.testzip()
                elif hasattr(target, 'testrar'):
                    target.testrar()
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
            color.greenln('\n成功从数据库中获得密码')
            color.redln(self.__password)
            return self.extractall(input_file, output, password) if extractall else password

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
            color.greenln('\n成功从字典中获得密码')
            color.redln(self.__password)
            self.db.insert_password(md5, self.__password)
            return self.__password

        color.cyanln('未发现密码')


if __name__ == "__main__":
    keeper = ZipCracker('storage/source.dat', start=0)
    input_file = 'storage/zip/zip.zip'
    keeper.find_password(input_file, max_threads=1, extractall=True)
