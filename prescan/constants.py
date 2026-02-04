"""
Constants, pattern lists, and configuration values for the WordPress pre-scanner.
"""

import re

# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

MAX_FILE_CONTENT_SIZE = 10 * 1024  # 10KB per included file; truncate beyond this
MAX_FILE_READ_SIZE = 10 * 1024 * 1024  # 10MB — skip files larger than this before read_text()
MAX_FILE_COUNT = 500_000  # Stop scanning after this many files to prevent runaway processing
MAX_GZIP_DECOMPRESSED_BYTES = 5 * 1024 * 1024 * 1024  # 5GB — abort gzipped SQL reads beyond this
PROGRESS_INTERVAL = 5000  # Print progress every N files

# ---------------------------------------------------------------------------
# Slug/version sanitization (SEC-07)
# ---------------------------------------------------------------------------

MAX_SLUG_LENGTH = 100
MAX_VERSION_LENGTH = 30
MAX_NAME_LENGTH = 200
VALID_SLUG_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
VALID_VERSION_RE = re.compile(r'^[\d.]+[a-zA-Z0-9.\-]*$')

# ---------------------------------------------------------------------------
# PHP patterns
# ---------------------------------------------------------------------------

PHP_EXTENSIONS = ('*.php', '*.phtml', '*.php5', '*.php7', '*.phar', '*.inc')

PHP_SUSPICIOUS_PATTERNS = [
    # Obfuscation / backdoors
    (r'eval\s*\(\s*base64_decode\s*\(', 'eval(base64_decode())'),
    (r'eval\s*\(\s*gzinflate\s*\(', 'eval(gzinflate())'),
    (r'eval\s*\(\s*gzuncompress\s*\(', 'eval(gzuncompress())'),
    (r'eval\s*\(\s*gzdecode\s*\(', 'eval(gzdecode())'),
    (r'eval\s*\(\s*str_rot13\s*\(', 'eval(str_rot13())'),
    (r'\bstr_rot13\s*\(', 'str_rot13()'),
    (r'\bgzinflate\s*\(', 'gzinflate()'),
    (r'\bgzuncompress\s*\(', 'gzuncompress()'),
    (r'\bgzdecode\s*\(', 'gzdecode()'),
    (r'preg_replace\s*\(\s*["\'][^"\']*\/e["\']', 'preg_replace /e modifier'),
    (r'preg_replace_callback\s*\(\s*[^)]*\$', 'preg_replace_callback with dynamic callback'),
    (r'\bcreate_function\s*\(', 'create_function()'),
    (r'\bassert\s*\(\s*\$', 'assert() with dynamic string'),
    (r'(\\x[0-9a-fA-F]{2}){4,}', 'hex-encoded string'),
    (r'chr\s*\(\s*\d+\s*\)\s*\..*chr\s*\(\s*\d+\s*\)\s*\..*chr\s*\(\s*\d+\s*\)', 'chr() chain obfuscation'),
    (r'\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(', '$_SUPERGLOBAL used as callable'),
    (r'\$\{\s*[\'"]', 'encoded variable function ${\'...'),
    (r'\$\$\w+', 'variable variable ($$var)'),
    (r'call_user_func(_array)?\s*\(\s*\$', 'call_user_func with dynamic arg'),
    # Shell execution
    (r'\bshell_exec\s*\(', 'shell_exec()'),
    (r'\bpassthru\s*\(', 'passthru()'),
    (r'\bproc_open\s*\(', 'proc_open()'),
    (r'\bpopen\s*\(', 'popen()'),
    (r'\bpcntl_exec\s*\(', 'pcntl_exec()'),
    (r'\bexec\s*\(\s*\$', 'exec() with dynamic arg'),
    (r'\bsystem\s*\(\s*\$', 'system() with dynamic arg'),
    # File operations (dropper / persistence)
    (r'file_put_contents\s*\(\s*\$', 'file_put_contents with dynamic path'),
    (r'@include\s*\(\s*\$', '@include with variable path'),
    (r'@include\s*\(\s*[\'"][\w/\\\\]+\.(ico|jpg|png|gif)', '@include of non-PHP extension'),
    # Network callbacks
    (r'\bcurl_exec\s*\(', 'curl_exec()'),
    (r'wp_remote_(get|post|request)\s*\(\s*\$', 'wp_remote with dynamic URL'),
    (r'fsockopen\s*\(', 'fsockopen()'),
    # Webshells
    (r'FilesMan', 'webshell: FilesMan'),
    (r'\bWSO\b', 'webshell: WSO'),
    (r'\bb374k\b', 'webshell: b374k'),
    (r'\bc99shell\b', 'webshell: c99'),
    (r'\br57shell\b', 'webshell: r57'),
    (r'@ini_set\s*\(\s*[\'"]error_log[\'"]\s*,\s*NULL\s*\)', 'webshell indicator: error_log=NULL'),
    (r'@ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*0\s*\)', 'webshell indicator: display_errors=0'),
    # Goto obfuscation
    (r'^\s*goto\s+\w+\s*;', 'goto-based obfuscation'),
    # Miners
    (r'CoinHive', 'crypto miner: CoinHive'),
    (r'coinhive\.min\.js', 'crypto miner: coinhive.min.js'),
    # WP-specific
    (r'wp_cd_code', 'WP-VCD: wp_cd_code'),
    (r'wp_cd_key', 'WP-VCD: wp_cd_key'),
    (r'move_uploaded_file\s*\(', 'file upload: move_uploaded_file'),
    (r'wp_insert_user\s*\(', 'user creation: wp_insert_user'),
    (r'wp_create_user\s*\(', 'user creation: wp_create_user'),
    (r'document\.write\s*\(', 'document.write()'),
    (r'unescape\s*\(', 'unescape()'),
    (r'<iframe', 'iframe injection'),
]

# ---------------------------------------------------------------------------
# Database patterns
# ---------------------------------------------------------------------------

DB_SUSPICIOUS_PATTERNS = [
    (r'<script\b', 'script tag'),
    (r'\beval\s*\(', 'eval()'),
    (r'base64_decode', 'base64_decode'),
    (r'document\.write', 'document.write'),
    (r'String\.fromCharCode', 'String.fromCharCode'),
    (r'window\.location\s*=', 'window.location redirect'),
    (r'\bunescape\s*\(', 'unescape()'),
    (r'<iframe', 'hidden iframe'),
    (r'<\?php', 'PHP tag in database'),
    (r'wp_cd_code', 'WP-VCD: wp_cd_code'),
    (r'wp_cd_key', 'WP-VCD: wp_cd_key'),
    # Whitespace-obfuscated payloads (DB-04): active content hidden behind
    # excessive blank lines to push it below visible area in admin UIs
    (r'(?:\r?\n\s*){10,}(?:<script|<iframe|<\?php|\beval\s*\()', 'whitespace-obfuscated payload'),
]

INJECTION_OPTION_RE = re.compile(
    r'insert_header|insert_footer'
    r'|header_code|footer_code'
    r'|head_script|body_script|footer_script'
    r'|tracking_code|tracking_script'
    r'|custom_css|custom_js'
    r'|custom_head|custom_header|custom_footer'
    r'|analytics_code|analytics_script'
    r'|ihaf_',
    re.I
)

# ---------------------------------------------------------------------------
# Error log patterns
# ---------------------------------------------------------------------------

MAX_LOG_READ_BYTES = 5 * 1024 * 1024       # 5MB tail per log file
MAX_TOTAL_LOG_BYTES = 20 * 1024 * 1024      # 20MB total across all files
MAX_LOG_ENTRIES = 5000                       # Max parsed entries per file
MAX_LOG_FILES = 50                           # Max log files to process
MAX_LOG_ENTRIES_PER_CATEGORY = 100           # Max entries kept per security category
MAX_LOG_TIMELINE_EVENTS = 200               # Max timeline events

ERROR_LOG_KNOWN_PATHS = [
    'error_log',
    'php-errors.log',
    'wp-content/debug.log',
    'wp-content/php-errors.log',
    'logs/error.log',
    'logs/php-errors.log',
    'logs/error_log',
]

ERROR_LOG_GLOB_PATTERNS = [
    '*.log',
    'wp-content/*.log',
    'logs/*.log',
    'logs/*error*',
    'wp-content/logs/*.log',
]

LOG_TIMESTAMP_RE = re.compile(
    r'\[(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+\w+)?)\]'
    r'|'
    r'\[(\d{4}-\d{2}-\d{2}(?:T|\s)\d{2}:\d{2}:\d{2}[^\]]*)\]'
)

LOG_LEVEL_RE = re.compile(
    r'PHP\s+(Fatal\s+error|Parse\s+error|Warning|Notice|Deprecated|Strict\s+Standards)',
    re.I
)

LOG_FILE_REF_RE = re.compile(r'in\s+(\S+\.php)\s+on\s+line\s+(\d+)')

LOG_SECURITY_PATTERNS = {
    'auth_manipulation': [
        (r'wp_set_password', 'wp_set_password'),
        (r'wp_insert_user', 'wp_insert_user'),
        (r'wp_create_user', 'wp_create_user'),
        (r'wp_update_user', 'wp_update_user'),
        (r'add_role|set_role', 'role_change'),
    ],
    'auth_event': [
        (r'wp_set_auth_cookie', 'wp_set_auth_cookie'),
        (r'auto.?login', 'auto_login'),
        (r'wp_signon', 'wp_signon'),
        (r'wp_logout', 'wp_logout'),
    ],
    'file_operation': [
        (r'file_put_contents', 'file_put_contents'),
        (r'move_uploaded_file', 'move_uploaded_file'),
        (r'fwrite', 'fwrite'),
        (r'file_get_contents\s*\(\s*[\'"]https?://', 'remote_file_get'),
    ],
    'code_execution': [
        (r'\beval\b', 'eval'),
        (r'base64_decode', 'base64_decode'),
        (r'create_function', 'create_function'),
        (r'assert\s*\(', 'assert'),
    ],
    'shell_execution': [
        (r'\bexec\s*\(', 'exec'),
        (r'shell_exec', 'shell_exec'),
        (r'\bsystem\s*\(', 'system'),
        (r'passthru', 'passthru'),
        (r'proc_open', 'proc_open'),
    ],
    'network_callback': [
        (r'curl_exec', 'curl_exec'),
        (r'fsockopen', 'fsockopen'),
        (r'wp_remote_(get|post|request)', 'wp_remote'),
    ],
    'known_malware': [
        (r'wp-vcd', 'wp_vcd'),
        (r'FilesMan', 'FilesMan'),
        (r'c99shell', 'c99shell'),
        (r'r57shell', 'r57shell'),
        (r'b374k', 'b374k'),
    ],
    'code_injection_indicator': [
        (r'Cannot redeclare', 'cannot_redeclare'),
        (r'Cannot modify header', 'cannot_modify_header'),
        (r'headers already sent', 'headers_already_sent'),
    ],
    'missing_file': [
        (r'failed to open stream.*No such file', 'missing_file'),
        (r'require.*failed opening required', 'failed_require'),
        (r'include.*failed opening', 'failed_include'),
    ],
}

# ---------------------------------------------------------------------------
# Security plugin log patterns (SCAN-02)
# ---------------------------------------------------------------------------

MAX_SECURITY_LOG_FILES = 100
MAX_SECURITY_LOG_READ_BYTES = 5 * 1024 * 1024  # 5MB per file
MAX_SECURITY_LOG_TOTAL_BYTES = 30 * 1024 * 1024  # 30MB total
MAX_SECURITY_LOG_ENTRIES = 500  # Max entries to include in output

# Known security plugin log directories (relative to wp-content/)
SECURITY_LOG_DIRS = [
    'wflogs',                           # Wordfence
    'plugins/wordfence/tmp',            # Wordfence tmp
    'uploads/sucuri',                   # Sucuri
    'plugins/sucuri-scanner/logs',      # Sucuri scanner
    'uploads/shield',                   # Shield Security
    'plugins/better-wp-security/logs',  # iThemes/SolidWP Security
    'uploads/mainwp',                   # MainWP
    'plugins/all-in-one-wp-security-and-firewall/logs',  # AIOS
]

# Patterns to extract from security plugin logs
SECURITY_LOG_PATTERNS = {
    'blocked_attack': [
        (r'blocked.*(?:sql|xss|rfi|lfi|rce|traversal)', 'blocked_attack'),
        (r'firewall.*block', 'firewall_block'),
        (r'waf.*block', 'waf_block'),
    ],
    'login_attempt': [
        (r'login.*(?:fail|invalid|locked|blocked)', 'failed_login'),
        (r'brute.?force', 'brute_force'),
        (r'lockout', 'lockout'),
    ],
    'file_change': [
        (r'file.*(?:modif|chang|added|deleted)', 'file_change'),
        (r'integrity.*(?:fail|changed)', 'integrity_check'),
    ],
    'malware_detection': [
        (r'malware.*(?:found|detected|scan)', 'malware_found'),
        (r'suspicious.*(?:file|code)', 'suspicious_detected'),
        (r'quarantin', 'quarantine'),
    ],
    'config_change': [
        (r'(?:option|setting|config).*(?:changed|updated|modified)', 'config_change'),
        (r'firewall.*(?:enabled|disabled|mode)', 'firewall_config'),
    ],
}

# ---------------------------------------------------------------------------
# WordPress reference data
# ---------------------------------------------------------------------------

STANDARD_ROOT_PHP = {
    'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
    'wp-config.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
    'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
    'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
}

STANDARD_WP_TABLES = {
    'commentmeta', 'comments', 'links', 'options', 'postmeta', 'posts',
    'terms', 'termmeta', 'term_relationships', 'term_taxonomy', 'usermeta', 'users',
}

CORE_FILES_TO_INSPECT = [
    'wp-config.php', 'index.php', 'wp-blog-header.php', 'wp-settings.php',
    'wp-load.php', 'wp-login.php', 'wp-cron.php', 'xmlrpc.php',
    'wp-admin/admin-ajax.php',
]

KNOWN_MALWARE_FILENAMES = {
    'wp-tmp.php', 'wp-vcd.php', 'class.theme-modules.php', 'wp-feed.php',
    'wp-cfg.php', 'db_session.php', 'null.php', 'cmd.php',
}

LEGITIMATE_PATHS = [
    '/vendor/', '/node_modules/', '/Monolog/', '/mPDF/', '/mpdf/',
    '/elFinder/', '/elfinder/', '/PHPMailer/', '/phpmailer/',
    '/phpseclib/', '/Symfony/', '/symfony/', '/guzzle/', '/Guzzle/',
    '/paragonie/', '/firebase/', '/google/', '/aws-sdk/',
]

HIGH_SIGNAL_PATTERNS = {
    'eval(base64_decode())', 'eval(gzinflate())', 'eval(gzuncompress())',
    'eval(gzdecode())', 'eval(str_rot13())', 'webshell: FilesMan',
    'webshell: WSO', 'webshell: b374k', 'webshell: c99', 'webshell: r57',
    'WP-VCD: wp_cd_code', 'WP-VCD: wp_cd_key', 'chr() chain obfuscation',
}

SENSITIVE_WP_DEFINES = {
    'DB_PASSWORD',
    'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
    'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
}
