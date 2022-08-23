import psycopg2
import os
import re
import sqlite3
from algosdk.logic import get_application_address
import sys 
sys.path.append("..")
import setting

def get_app_algos():
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
    #print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select index from app where deleted=false")
    result_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    #print("contracts number: {}".format(len(result_list)))

    total_amount = 0
    for item in result_list:
        appID = item[0]
        address = (get_application_address(appID))
        account_info = setting.algod_client.account_info(address)
        total_amount += account_info["amount"]
        #print(total_amount)
    
    print("get_app_algos: {}".format(total_amount))

def get_txn_algos():
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
    #print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select SUM((txn->'txn'->>'amt')::bigint) from txn where txn::jsonb ? 'lsig' and txn->'txn'->>'type'='pay'")
    result = blockchain_cursor.fetchall()
    blockchain_connection.close()
    print(result)


if __name__ == '__main__':
    get_txn_algos()
    get_app_algos()