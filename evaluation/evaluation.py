import sqlite3
import sys 
sys.path.append("..")
import setting

def evaluation_contract(db_name):
    final_db_path = setting.DB_PATH + db_name
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where opcode_kinds > 0")
    total_number = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where opcode_kinds > 0")
    total_number_unique = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(run_time) from contracts where opcode_kinds > 0")
    run_time_sum = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("SELECT run_time FROM contracts where opcode_kinds > 0 ORDER BY run_time LIMIT 1 OFFSET (SELECT COUNT(*) FROM contracts where opcode_kinds > 0) / 2")
    run_time_medium = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(leaves_number) from contracts where opcode_kinds > 0")
    path_sum = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("SELECT leaves_number FROM contracts where opcode_kinds > 0 ORDER BY leaves_number LIMIT 1 OFFSET (SELECT COUNT(*) FROM contracts where opcode_kinds > 0) / 2")
    path_medium = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(opcodes) from contracts where opcode_kinds > 0")
    opcodes = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(opcode_kinds) from contracts where opcode_kinds > 0")
    opcode_kinds = final_sqlite_cursor.fetchall()[0][0]

    print("total_number: {}".format(total_number))
    print("total_number_unique: {}".format(total_number_unique))
    print("run_time_sum: {:.2f}s({:.2f} days)".format(run_time_sum,run_time_sum/24/3600))
    print("run_time_medium: {}".format(run_time_medium))
    print("run_time_average: {:.2f}".format(run_time_sum/total_number_unique))
    print("path_sum: {}".format(path_sum))
    print("path_medium: {}".format(path_medium))
    print("path_sum_average: {:.2f}".format(path_sum/total_number_unique))
    print("opcodes: {:.2f}".format(opcodes/total_number_unique))
    print("opcode_kinds: {:.2f}".format(opcode_kinds/total_number_unique))



    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where arbitrary_update=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where arbitrary_update=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("arbitrary_update, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where arbitrary_deletion=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where arbitrary_deletion=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("arbitrary_deletion, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where unchecked_group_size=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where unchecked_group_size=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_group_size, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where force_clear_state=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where force_clear_state=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("force_clear_state, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where unchecked_payment_receiver=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where unchecked_payment_receiver=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_payment_receiver, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where unchecked_asset_receiver=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where unchecked_asset_receiver=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_asset_receiver, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from contracts where time_stamp_dependeceny=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from contracts where time_stamp_dependeceny=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("time_stamp_dependeceny, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))


    final_sqlite_connection.close()





def evaluation_signature_no_app_call(dbname):
    final_db_path = setting.DB_PATH + dbname
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where contain_app_call=0 and opcode_kinds > 0")
    total_number = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where contain_app_call=0 and opcode_kinds > 0")
    total_number_unique = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(leaves_number) from signatures where contain_app_call=0 and opcode_kinds > 0")
    path_sum = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("SELECT leaves_number FROM signatures where contain_app_call=0  and opcode_kinds > 0 ORDER BY leaves_number LIMIT 1 OFFSET (SELECT COUNT(*) FROM signatures where contain_app_call=0 and opcode_kinds > 0) / 2")
    path_medium = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(opcodes) from signatures where contain_app_call=0 and opcode_kinds > 0")
    opcodes = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(opcode_kinds) from signatures where contain_app_call=0 and opcode_kinds > 0")
    opcode_kinds = final_sqlite_cursor.fetchall()[0][0]

    print("total_number: {}".format(total_number))
    print("total_number_unique: {}".format(total_number_unique))
    print("path_sum: {}".format(path_sum))
    print("path_medium: {}".format(path_medium))
    print("path_sum_average: {:.2f}".format(path_sum/total_number_unique))
    print("opcodes: {:.2f}".format(opcodes/total_number_unique))
    print("opcode_kinds: {:.2f}".format(opcode_kinds/total_number_unique))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_transaction_fees=1 and contain_app_call=0 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_transaction_fees=1 and contain_app_call=0 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_transaction_fees, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_rekey_to=1 and contain_app_call=0 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_rekey_to=1 and contain_app_call=0 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_rekey_to, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_close_remainder_to=1 and contain_app_call=0 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_close_remainder_to=1 and contain_app_call=0 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_close_remainder_to, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_asset_close_to=1 and contain_app_call=0 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_asset_close_to=1 and contain_app_call=0 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_asset_close_to, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_connection.close()



def evaluation_signature(dbname):
    final_db_path = setting.DB_PATH + dbname
    final_sqlite_connection = sqlite3.connect(final_db_path)
    final_sqlite_cursor = final_sqlite_connection.cursor()

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where contain_app_call=1 and opcode_kinds > 0")
    total_number = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where contain_app_call=1 and opcode_kinds > 0")
    total_number_unique = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where opcode_kinds > 0")
    total_number_unique_all = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(run_time) from signatures where opcode_kinds > 0")
    run_time_sum = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("SELECT run_time FROM signatures where opcode_kinds > 0 ORDER BY run_time LIMIT 1 OFFSET (SELECT COUNT(*) FROM signatures where opcode_kinds > 0) / 2")
    run_time_medium = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(leaves_number) from signatures where contain_app_call=1 and opcode_kinds > 0")
    path_sum = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("SELECT leaves_number FROM signatures where contain_app_call=1  and opcode_kinds > 0 ORDER BY leaves_number LIMIT 1 OFFSET (SELECT COUNT(*) FROM signatures where contain_app_call=1 and opcode_kinds > 0) / 2")
    path_medium = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(opcodes) from signatures where contain_app_call=1 and opcode_kinds > 0")
    opcodes = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select SUM(opcode_kinds) from signatures where contain_app_call=1 and opcode_kinds > 0")
    opcode_kinds = final_sqlite_cursor.fetchall()[0][0]

    print("total_number: {}".format(total_number))
    print("total_number_unique: {}".format(total_number_unique))
    print("run_time_sum: {:.2f}s({:.2f} days)".format(run_time_sum,run_time_sum/24/3600))
    print("run_time_medium: {}".format(run_time_medium))
    print("run_time_average: {:.2f}".format(run_time_sum/total_number_unique_all))
    print("path_sum: {}".format(path_sum))
    print("path_medium: {}".format(path_medium))
    print("path_sum_average: {:.2f}".format(path_sum/total_number_unique))
    print("opcodes: {:.2f}".format(opcodes/total_number_unique))
    print("opcode_kinds: {:.2f}".format(opcode_kinds/total_number_unique))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_transaction_fees=1 and contain_app_call=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_transaction_fees=1 and contain_app_call=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_transaction_fees, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_rekey_to=1 and contain_app_call=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_rekey_to=1 and contain_app_call=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_rekey_to, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_close_remainder_to=1 and contain_app_call=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_close_remainder_to=1 and contain_app_call=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_close_remainder_to, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_cursor.execute("select SUM(repeat_count) from signatures where unchecked_asset_close_to=1 and contain_app_call=1 and opcode_kinds > 0")
    total_result = final_sqlite_cursor.fetchall()[0][0]
    final_sqlite_cursor.execute("select COUNT(*) from signatures where unchecked_asset_close_to=1 and contain_app_call=1 and opcode_kinds > 0")
    unique_result = final_sqlite_cursor.fetchall()[0][0]
    print("unchecked_asset_close_to, total: {}({:.2f}%), unqiue: {}({:.2f}%)".format(total_result, 
        total_result/total_number*100, unique_result, unique_result/total_number_unique*100))

    final_sqlite_connection.close()





if __name__ == '__main__':
    print("=========================================")
    evaluation_contract("combined_contract_db.sqlite3") # 33671, 9894
    print("=========================================")
    evaluation_contract("combined_static_contract_db.sqlite3") # 299021, 50057
    print("=========================================")
    evaluation_signature("combined_account_signature_db.sqlite3")
    print("=========================================")
    evaluation_signature_no_app_call("combined_account_signature_db.sqlite3")
    print("=========================================")