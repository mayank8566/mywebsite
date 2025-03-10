import multiprocessing

# Bind to this socket
bind = "0.0.0.0:8000"

# Number of worker processes
workers = multiprocessing.cpu_count() * 2 + 1

# Type of workers to use
worker_class = "gevent"

# Timeout for worker processes
timeout = 120

# Logging
accesslog = "logs/access.log"
errorlog = "logs/error.log"
loglevel = "info"

# Daemonize the process
daemon = False

# Process name
proc_name = "cosmic_teams"

# For hosting environments that require it
forwarded_allow_ips = '*'
secure_scheme_headers = {'X-Forwarded-Proto': 'https'}

# SSL configuration (uncomment and set paths for HTTPS)
# certfile = "path/to/cert.pem"
# keyfile = "path/to/key.pem" 