import sqlite3
import json
import os
import base64
from algosdk.v2client import indexer
from algosdk.future import transaction
import sys 
sys.path.append("..")
import setting
import util


myindexer = indexer.IndexerClient(indexer_token="", indexer_address="http://localhost:8980")


sqlite_connection = sqlite3.connect(setting.DB_PATH + "combined_segfault_final_signature_db.sqlite3")
sqlite_cursor = sqlite_connection.cursor()
sqlite_cursor.execute("select * from signatures")
signature_list = sqlite_cursor.fetchall()
sqlite_connection.close()


sqlite_connection = sqlite3.connect(setting.DB_PATH + "combined_segfault_final_signature_db.sqlite3")
sqlite_cursor = sqlite_connection.cursor()
count = 0
for item in signature_list:
    count += 1
    program = item[0]
    fname = util.decompile(program)
    response = setting.algod_client.compile(open(fname,"r").read())
    programstr = response['result']
    bytecodes = base64.decodebytes(programstr.encode())
    lsig = transaction.LogicSig(bytecodes)
    os.unlink(fname)

    try:
        response = myindexer.account_info(address=lsig.address(), include_all=True)
        signature_account = 1
    except:
        signature_account = 0
    print("{}:{}".format(count, signature_account))
    sqlite_cursor.execute("update signatures set type={} where program='{}'".format(signature_account, program))
sqlite_connection.commit()
sqlite_connection.close()