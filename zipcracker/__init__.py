'''
Date: 2020-12-24 16:44:09
LastEditors: Rustle Karl
LastEditTime: 2020-12-24 20:44:54
'''
from .zipcracker import ZipCracker
import color


def zipcracker(input_file=None, extractall=False):
    import sys

    if len(sys.argv) > 1:
        input_file = sys.argv[1]

    if input_file is None:
        color.redln('错误: 未输入文件')
        return

    cracker = ZipCracker()
    cracker.find_password(input_file, max_threads=1, extractall=extractall)

    input('\n请关闭窗口退出')
