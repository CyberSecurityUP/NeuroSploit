import re

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning: mysql_",
    r"Unclosed quotation mark",
    r"SQLSTATE\[HY000\]",
    r"You have an error in your SQL syntax",
]
compiled = [re.compile(p, re.IGNORECASE) for p in SQL_ERRORS]

def has_sql_error(text: str) -> bool:
    return any(c.search(text) for c in compiled)
