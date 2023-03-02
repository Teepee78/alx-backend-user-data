#!/usr/bin/env python3
"""
Defines the filter_datum function
"""
import logging
import os
import re
from typing import List

import mysql.connector

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(
    fields: List[str],
    redaction: str,
    message: str,
    separator: str
) -> str:
    """Returns the log message obfuscated

    Args:
        fields (List[str]): all fields to obfuscate
        redaction (str): what the field will be obfuscated with
        message (str): the log line
        separator (str): separator string

    Returns:
        str: log message
    """
    for field in fields:
        repl = field + "=" + redaction + separator
        message = re.sub(field + r"=.*?" + separator, repl, message)
    return message


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Init method"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a log record

        Args:
            record (logging.LogRecord): log record

        Returns:
            str: formatted record
        """
        message = super(RedactingFormatter, self).format(record)
        return filter_datum(
            self.fields, self.REDACTION, message, self.SEPARATOR
        )


def get_logger() -> logging.Logger:
    """Returns logger object"""

    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Connects to the database
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or "root"
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ""
    host = os.getenv('PERSONAL_DATA_DB_HOST') or "localhost"
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    connect = mysql.connector.connect(
        user=user,
        password=passwd,
        host=host,
        database=db_name)
    return connect


def main():
    """Entry point"""

    db = get_db()
    logger = get_logger()

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    fields = cursor.column_names
    for row in cursor:
        message = "".join("{}={}; ".format(k, v) for k, v in zip(fields, row))
        logger.info(message.strip())
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
