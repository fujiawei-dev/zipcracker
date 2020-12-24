'''
Date: 2020-12-24 10:12:56
LastEditors: Rustle Karl
LastEditTime: 2020-12-24 13:39:07
'''

from checksum import md5 as checksum_md5
from peewee import CharField, Database, DoesNotExist, Model, SqliteDatabase


class ZipMd5(object):

    def __init__(self, database='storage/zipmd5.db', **options) -> None:

        if isinstance(database, str):
            self.db = SqliteDatabase(database, **options)
        elif isinstance(database, Database):
            self.db = database
        else:
            raise ValueError(database)

        self.model = self.__get_model()

    def __get_model(self):

        class Md5Password(Model):
            md5 = CharField(primary_key=True)
            password = CharField()

            class Meta:
                database = self.db

        self.db.create_tables([Md5Password], safe=True)

        return Md5Password

    def insert_password(self, md5, password):
        self.model.create(md5=md5, password=password)

    def insert(self, path, password):
        self.insert_password(checksum_md5(path), password)

    def get_password_by_md5(self, md5):
        return self.model.get(self.model.md5 == md5).password

    def get_password(self, path):
        md5 = checksum_md5(path)
        password = ''
        try:
            password = self.get_password_by_md5(md5)
        except DoesNotExist:
            pass
        return password, md5


if __name__ == "__main__":
    zipmd5 = ZipMd5()
    print(zipmd5.get_password_by_md5('test'))
