import psycopg2
from algosdk.logic import get_application_address
import os
import sqlite3
import re
import hashlib
import tempfile
import sys 
sys.path.append("..")
import setting
import util


def attack1():
    blockchain_connection = psycopg2.connect(database=setting.ALGO_DB, 
                                            user=setting.ALGO_USER, 
                                            password=setting.ALGO_PWD, 
                                            host=setting.ALGO_HOST, 
                                            port=setting.ALGO_PORT,
                                            keepalives=1,
                                            keepalives_idle=60,
                                            keepalives_interval=10,
                                            keepalives_count=15,
                                            )
    blockchain_cursor = blockchain_connection.cursor()


    db_path = setting.DB_PATH + "combined_contract_db.sqlite3"
    sqlite_connection = sqlite3.connect(db_path)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute("select program from contracts where arbitrary_update=1")
    app_list = sqlite_cursor.fetchall()
    for item in app_list:
        program = item[0]
        blockchain_cursor.execute("select index from app where deleted=false and params->>'approv'='{}'".format(program))
        appID_list = blockchain_cursor.fetchall()
        if len(appID_list) > 0:
            for appID in appID_list:
                address = get_application_address(appID[0])
                account_info = setting.algod_client.account_info(address)
                if int(account_info["amount"]) > 0:
                    print(account_info["amount"])

    sqlite_cursor.close()
    blockchain_connection.close()



if __name__ == '__main__':
    attack1()


