#!/bin/bash

##############################################################################
# NGINX High-Performance Proxy Installation Script
# For Ubuntu 20.04/22.04/24.04
# Usage: echo "youremail@example.com" | sudo ./install-nginx-proxy.sh
#    Or: sudo ./install-nginx-proxy.sh youremail@example.com
##############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Get email from arguments or stdin
if [ $# -eq 1 ]; then
    # From command line argument
    EMAIL="$1"
else
    # From stdin
    read EMAIL
fi

# Validate email
if [[ -z "$EMAIL" ]]; then
    log_error "Email is required!"
    log_error "Usage: echo \"email@example.com\" | sudo $0"
    log_error "   Or: sudo $0 email@example.com"
    exit 1
fi

# Validate email format
if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    log_error "Invalid email format: $EMAIL"
    exit 1
fi

log_info "Starting NGINX installation and configuration..."
log_info "Email: $EMAIL"

##############################################################################
# 1. Get Public IP and Generate Domain
##############################################################################
log_info "Detecting public IP address..."

# Try multiple methods to get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com || curl -s https://api.ipify.org || curl -s https://ifconfig.me)

if [[ -z "$PUBLIC_IP" ]]; then
    log_error "Could not detect public IP address"
    exit 1
fi

log_info "Public IP detected: $PUBLIC_IP"

# Auto-generate domain using nip.io
DOMAIN="${PUBLIC_IP}.nip.io"
log_info "Using auto-generated domain: $DOMAIN"

##############################################################################
# 2. Update System
##############################################################################
log_info "Updating system packages..."
apt update -qq
apt upgrade -y -qq

##############################################################################
# 3. Install NGINX
##############################################################################
log_info "Installing NGINX..."
apt install -y nginx

# Stop nginx for certbot
systemctl stop nginx

##############################################################################
# 4. Install Certbot
##############################################################################
log_info "Installing Certbot..."
apt install -y certbot python3-certbot-nginx

##############################################################################
# 5. Obtain SSL Certificate
##############################################################################
log_info "Obtaining SSL certificate from Let's Encrypt for: $DOMAIN..."

certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN" \
    --preferred-challenges http 2>&1 | tee /tmp/certbot.log

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    log_error "Failed to obtain SSL certificate from Let's Encrypt"
    
    # Check if it's a DNS issue
    if grep -q "DNS problem" /tmp/certbot.log; then
        log_error "DNS is not properly configured for $DOMAIN"
    fi
    
    log_warn "Falling back to self-signed certificate..."
    
    mkdir -p /etc/nginx/ssl
    
    # Create OpenSSL config for IP SAN
    cat > /tmp/openssl-ip.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext
x509_extensions = v3_ca

[dn]
CN = $DOMAIN

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = $DOMAIN
IP.1 = $PUBLIC_IP
EOF

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/selfsigned.key \
        -out /etc/nginx/ssl/selfsigned.crt \
        -config /tmp/openssl-ip.cnf 2>/dev/null
    
    rm /tmp/openssl-ip.cnf
    
    SSL_CERT="/etc/nginx/ssl/selfsigned.crt"
    SSL_KEY="/etc/nginx/ssl/selfsigned.key"
    CERT_FAILED=1
    
    log_warn "✅ Self-signed certificate created"
    log_warn "⚠️  Browsers will show security warnings!"
else
    SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    CERT_FAILED=0
    log_info "✅ Let's Encrypt SSL certificate obtained successfully!"
fi

rm -f /tmp/certbot.log

##############################################################################
# 6. Optimize System Limits
##############################################################################
log_info "Optimizing system limits..."

# Increase file descriptor limits
if ! grep -q "www-data soft nofile" /etc/security/limits.conf; then
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 65535
* hard nofile 65535
www-data soft nofile 65535
www-data hard nofile 65535
EOF
fi

# Increase system-wide limits
if ! grep -q "# NGINX Optimization" /etc/sysctl.conf; then
    cat >> /etc/sysctl.conf <<EOF

# NGINX Optimization
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.core.netdev_max_backlog = 65535
EOF
fi

sysctl -p > /dev/null 2>&1

##############################################################################
# 7. Create NGINX Configuration
##############################################################################
log_info "Creating NGINX configuration..."

cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    use epoll;
    worker_connections 16384;
    multi_accept on;
}

http {
    resolver 1.1.1.1 8.8.8.8 valid=30s;
    resolver_timeout 5s;

    access_log off;
    error_log /var/log/nginx/error.log crit;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    map $request_uri $target_uri {
        ~^/(https?://.*)$ $1;
        default "";
    }

    map $target_uri $target_host {
        ~^https?://([^/]+) $1;
        default "";
    }

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    server {
        listen 80 reuseport;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2 reuseport;
        server_name _;

        ssl_certificate SSL_CERT_PATH;
        ssl_certificate_key SSL_KEY_PATH;

        client_max_body_size 10m;
        client_body_buffer_size 128k;
        proxy_buffering off;

        location / {
            if ($target_uri = "") {
                return 400 "Missing target URL. Usage: https://your-domain/https://api.example.com/endpoint";
            }

            if ($request_method = 'OPTIONS') {
                add_header 'Access-Control-Allow-Origin' '*' always;
                add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
                add_header 'Access-Control-Allow-Headers' '*' always;
                add_header 'Access-Control-Max-Age' 1728000;
                add_header 'Content-Type' 'text/plain; charset=utf-8';
                add_header 'Content-Length' 0;
                return 204;
            }

            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
            add_header Access-Control-Expose-Headers "Content-Length, Date" always;

            proxy_pass $target_uri;
            proxy_ssl_server_name on;
            proxy_ssl_name $target_host;
            proxy_ssl_protocols TLSv1.2 TLSv1.3;
            proxy_ssl_session_reuse on;

            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $target_host;
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Real-IP "";

            proxy_hide_header Access-Control-Allow-Origin;
            proxy_hide_header Access-Control-Allow-Methods;
            proxy_hide_header Access-Control-Allow-Headers;

            proxy_connect_timeout 10s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }

        location /health {
            access_log off;
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

# Replace SSL certificate paths
sed -i "s|SSL_CERT_PATH|$SSL_CERT|g" /etc/nginx/nginx.conf
sed -i "s|SSL_KEY_PATH|$SSL_KEY|g" /etc/nginx/nginx.conf

##############################################################################
# 8. Test Configuration
##############################################################################
log_info "Testing NGINX configuration..."
nginx -t

if [ $? -ne 0 ]; then
    log_error "NGINX configuration test failed!"
    exit 1
fi

##############################################################################
# 9. Setup Certbot Auto-Renewal (only for Let's Encrypt)
##############################################################################
if [ $CERT_FAILED -eq 0 ]; then
    log_info "Setting up SSL certificate auto-renewal..."

    # Create renewal hook to reload nginx
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOFHOOK'
#!/bin/bash
systemctl reload nginx
EOFHOOK

    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

    # Test renewal (suppress output)
    certbot renew --dry-run > /dev/null 2>&1 || log_warn "Certbot renewal test had warnings"
fi

##############################################################################
# 10. Configure Firewall (if UFW is installed)
##############################################################################
if command -v ufw &> /dev/null; then
    log_info "Configuring firewall..."
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
fi

##############################################################################
# 11. Start NGINX
##############################################################################
log_info "Starting NGINX..."
systemctl enable nginx > /dev/null 2>&1
systemctl start nginx

##############################################################################
# 12. Verify Installation
##############################################################################
log_info "Verifying installation..."

sleep 2

if systemctl is-active --quiet nginx; then
    log_info "✅ NGINX is running!"
else
    log_error "❌ NGINX failed to start"
    systemctl status nginx
    exit 1
fi

##############################################################################
# 13. Display Summary
##############################################################################
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          NGINX High-Performance Proxy - Installation Complete  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
log_info "Configuration Summary:"
echo "  • Public IP: $PUBLIC_IP"
echo "  • Domain: $DOMAIN (auto-generated)"
echo "  • Email: $EMAIL"
echo "  • HTTP Port: 80 (redirects to HTTPS)"
echo "  • HTTPS Port: 443"
if [ $CERT_FAILED -eq 1 ]; then
echo "  • SSL Type: ⚠️  Self-Signed (browsers will show warnings)"
else
echo "  • SSL Type: ✅ Let's Encrypt (trusted)"
fi
echo "  • SSL Certificate: $SSL_CERT"
echo "  • SSL Key: $SSL_KEY"
echo "  • Config File: /etc/nginx/nginx.conf"
echo "  • Error Log: /var/log/nginx/error.log"
echo ""
log_info "Usage Examples:"
echo "  # Proxy to Binance API:"
if [ $CERT_FAILED -eq 1 ]; then
echo "  curl -k https://$DOMAIN/https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT"
else
echo "  curl https://$DOMAIN/https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT"
fi
echo ""
echo "  # From React/JavaScript:"
echo "  fetch('https://$DOMAIN/https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT')"
echo ""
log_info "Management Commands:"
echo "  • Test config:    nginx -t"
echo "  • Reload:         systemctl reload nginx"
echo "  • Restart:        systemctl restart nginx"
echo "  • Status:         systemctl status nginx"
echo "  • Logs:           tail -f /var/log/nginx/error.log"
if [ $CERT_FAILED -eq 0 ]; then
echo "  • Renew SSL:      certbot renew"
fi
echo ""
log_info "Health Check:"
if [ $CERT_FAILED -eq 1 ]; then
echo "  curl -k https://$DOMAIN/health"
else
echo "  curl https://$DOMAIN/health"
fi
echo ""
if [ $CERT_FAILED -eq 0 ]; then
log_info "SSL Certificate Auto-Renewal:"
echo "  • Certbot will automatically renew certificates"
echo "  • Test renewal: certbot renew --dry-run"
echo "  • NGINX will auto-reload after renewal"
echo ""
fi
echo "╔════════════════════════════════════════════════════════════════╗"
if [ $CERT_FAILED -eq 1 ]; then
echo "║  Installation complete with SELF-SIGNED SSL ⚠️                  ║"
else
echo "║  Installation successful! Your proxy is ready to use 🚀        ║"
fi
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
