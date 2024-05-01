import sqlite3
from pathlib import Path

class DatabaseScanner:
    def __init__(self, base_directory):
        self.base_directory = Path(base_directory)
        self.sensitive_keywords = [
            'username', 'user', 'password', 'pass', 'login', 'credential', 'passwd',
            'cookie', 'cookies', 'history', 'session', 'autofill', 'formdata',
            'bookmark', 'bookmarks', 'email', 'address', 'phone', 'number', 'contact', 'contacts',
            'profile', 'account', 'token', 'tokens', 'apikey', 'api_key', 'secret', 'secrets',
            'auth', 'authentication', 'credit', 'card', 'payment', 'billing', 'transaction', 'transactions',
            'wallet', 'account_number', 'account_info', 'location', 'longitude', 'latitude'
        ]
        ## Took out:
        '''
        url, urls, name,

        These were muddying up the output. Add back in if you want all that
        '''

    def is_sensitive_column(self, column_name):
        """Check if column names suggest sensitive content."""
        return any(keyword in column_name.lower() for keyword in self.sensitive_keywords)

    def print_sensitive_data(self, cursor, table_name, column_name):
        """Print the data found in a sensitive column, eliminating duplicates and empty values."""
        try:
            cursor.execute(f"SELECT DISTINCT {column_name} FROM {table_name} WHERE {column_name} IS NOT NULL AND TRIM({column_name}) != ''")
            rows = cursor.fetchall()
            if rows:
                print(f"[*] Data Found in {table_name}.{column_name}:")
                for row in rows:
                    print(f"    - {column_name}: {row[0]}")
        except Exception as e:
            print(f"Error querying data from {table_name}.{column_name}: {e}")

    def scan_databases(self):
        """Iterate through all .db files in the directory to find sensitive information."""
        for device_dir in self.base_directory.iterdir():  # Iterate through each device-specific directory
            if device_dir.is_dir():  # Check if it's a directory
                print(f"Scanning device directory: {device_dir.name}")
                for db_path in device_dir.rglob('*.db'):
                    try:
                        connection = sqlite3.connect(db_path)
                        cursor = connection.cursor()

                        # Get all tables in the database
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = cursor.fetchall()

                        # Check each table for columns that are likely to hold sensitive information
                        for table in tables:
                            table_name = table[0]
                            cursor.execute(f"PRAGMA table_info({table_name})")
                            columns = cursor.fetchall()

                            for column in columns:
                                column_name = column[1]  # Column names are in the second position in the result
                                if self.is_sensitive_column(column_name):
                                    self.print_sensitive_data(cursor, table_name, column_name)

                        connection.close()
                    except Exception as e:
                        print(f"Error processing {db_path}: {e}")

        print("Scanning complete.")

def main():
    db_scanner = DatabaseScanner('data/adb_pull_devices')
    db_scanner.scan_databases()

if __name__ == "__main__":
    main()
