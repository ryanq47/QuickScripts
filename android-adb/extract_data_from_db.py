import sqlite3
from pathlib import Path

class DatabaseScanner:
    def __init__(self, directory):
        self.db_directory = Path(directory)
        self.sensitive_keywords = ['username', 'user', 'password', 'pass', 'login', 'credential', 'passwd']

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
        for db_path in self.db_directory.rglob('*.db'):
            try:
                #print(f"Checking {db_path} for sensitive information...")
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
                            #print(f"Potential sensitive data column found: {table_name}.{column_name} in {db_path}")
                            self.print_sensitive_data(cursor, table_name, column_name)

                connection.close()
            except Exception as e:
                print(f"Error processing {db_path}: {e}")

        print("Scanning complete.")

def main():
    db_scanner = DatabaseScanner('data/adb_pull_databases')
    db_scanner.scan_databases()

if __name__ == "__main__":
    main()
