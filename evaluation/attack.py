import psycopg2
import os
import sqlite3
import re
import hashlib
import tempfile
import sys 
sys.path.append("..")
import setting
import util


def get_app(appID):
    blockchain_connection = psycopg2.connect(database="algorand", 
                                            user="algorand", 
                                            password="algorand", 
                                            host=setting.ALGO_HOST, 
                                            port=setting.ALGO_PORT,
                                            keepalives=1,
                                            keepalives_idle=60,
                                            keepalives_interval=10,
                                            keepalives_count=15,
                                            )
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select encode(creator::bytea, 'base64'), created_at from app where index={}".format(appID))
    result = blockchain_cursor.fetchall()
    creator = result[0][0]
    created_at = result[0][1]
    blockchain_cursor.execute("select txn->'txn'->>'apap' from txn where round={} and typeenum=6 and txn->'txn'->>'snd'='{}'".format(created_at, creator))
    app_data = blockchain_cursor.fetchall()[0][0]
    blockchain_connection.close()
    return app_data


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
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select txn->'txn'->>'snd', txn->'txn'->>'apid' from txn where (txn::jsonb->'txn'->>'apan')::integer=4")
    attack_list = blockchain_cursor.fetchall()
    print("Fetch attack list successfully")


    sqlite_connection = sqlite3.connect(setting.DB_PATH + "combined_static_contract_db.sqlite3")
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute("select program from contracts where arbitrary_update=1")
    program_list = sqlite_cursor.fetchall()
    sqlite_connection.close()
    program_dict = {}
    program_result = []
    for program in program_list:
        program_dict[program[0]] = 1
        program_result.append(program[0])
    print("program_dict: {}".format(len(program_dict)))

    count = 0
    for item in attack_list:
        sender = item[0]
        appID = item[1]
        blockchain_cursor.execute("select encode(creator::bytea, 'base64') from app where index={}".format(appID))
        app_data = blockchain_cursor.fetchall()
        if len(app_data) == 0:
            continue
        creator = app_data[0][0]
        if creator != sender and ( get_app(appID) in program_result ):
            count += 1
    print(len(attack_list), count)
    blockchain_connection.close()



def attack2():
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
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select txn->'txn'->>'snd', txn->'txn'->>'apid' from txn where (txn::jsonb->'txn'->>'apan')::integer=4")
    attack_list = blockchain_cursor.fetchall()
    print("Fetch attack list successfully")
    count = 0
    for item in attack_list:
        sender = item[0]
        appID = item[1]
        blockchain_cursor.execute("select encode(creator::bytea, 'base64') from app where index={}".format(appID))
        app_data = blockchain_cursor.fetchall()
        if len(app_data) == 0:
            continue
        creator = app_data[0][0]
        if creator != sender:
            count += 1
    print(len(attack_list), count)
    blockchain_connection.close()

# select count(txn->'lsig'->>'l') from txn where txn::jsonb ? 'lsig' and (txn::jsonb->'txn'->>'fee')::integer > 10000;
# select count(txn->'lsig'->>'l') from txn where txn::jsonb ? 'lsig' and txn::jsonb->'txn' ? 'rekey';
# select count(txn->'lsig'->>'l') from txn where txn::jsonb ? 'lsig' and txn::jsonb->'txn' ? 'close';
# select count(txn->'lsig'->>'l') from txn where txn::jsonb ? 'lsig' and txn::jsonb->'txn' ? 'aclose';

'''
Connected to the PostgreSQL
Fetch attack list successfully
228755 74825
Connected to the PostgreSQL
Fetch attack list successfully
41919 41246
'''

def attack3():
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
    print("Connected to the PostgreSQL")
    blockchain_cursor = blockchain_connection.cursor()
    blockchain_cursor.execute("select txn->'lsig'->>'l' from txn where txn::jsonb ? 'lsig' and txn::jsonb->'txn' ? 'aclose'")
    attack_list = blockchain_cursor.fetchall()
    blockchain_connection.close()
    print("Fetch attack list successfully")


    sqlite_connection = sqlite3.connect(setting.DB_PATH + "combined_segfault_final_signature_db.sqlite3")
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute("select program from signatures where unchecked_asset_close_to=1")
    program_list = sqlite_cursor.fetchall()
    sqlite_connection.close()

    program_dict = {}
    for program in program_list:
        program_dict[program[0]] = 1
    print("program_dict: {}".format(len(program_dict)))

    item_dict = {}
    for item in attack_list:
        item_dict[item[0]] = item
    print("item_dict: {}".format(len(item_dict)))

    count = 0
    for program in program_list:
        if program[0] in item_dict.keys():
            item_dict[program[0]] = None
            count += 1
    print("count: {}".format(count))

# rekeyto 4683 45 43
# close 16940 261121 16024
# fee 6800 42 0
# aclose 2726 242974 845
# delete 241 228755 3303
# update 233 41919 0


if __name__ == '__main__':
    attack3()


