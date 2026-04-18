#!/usr/bin/env bash
# MailTool installer — installs on a shared server, auto-configures Caddy or nginx,
# creates a systemd service, and obtains a Let's Encrypt TLS certificate.
set -euo pipefail

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ─── Config ───────────────────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/mailtool}"
LISTEN_PORT="${LISTEN_PORT:-5000}"
SERVICE_USER="${SERVICE_USER:-mailtool}"
DOMAIN="${DOMAIN:-}"          # set via env or prompted below
EMAIL="${EMAIL:-}"            # for Let's Encrypt

# ─── Root check ───────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root (sudo ./install.sh)"

# ─── Detect OS ────────────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"; PKG_INSTALL="apt-get install -y"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"; PKG_INSTALL="dnf install -y"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"; PKG_INSTALL="yum install -y"
else
    die "Unsupported package manager (expected apt/dnf/yum)"
fi
info "Package manager: $PKG_MGR"

# ─── Prompt for domain / email if not set ─────────────────────────────────────
if [[ -z "$DOMAIN" ]]; then
    read -rp "Domain to serve MailTool on (e.g. mailtool.example.com): " DOMAIN
    [[ -n "$DOMAIN" ]] || die "Domain is required"
fi
if [[ -z "$EMAIL" ]]; then
    read -rp "Email address for Let's Encrypt notifications: " EMAIL
    [[ -n "$EMAIL" ]] || die "Email is required"
fi
info "Domain: $DOMAIN  |  Email: $EMAIL"

# ─── Install Python ───────────────────────────────────────────────────────────
info "Checking Python 3.10+..."
if ! python3 --version 2>/dev/null | grep -qE '3\.(1[0-9]|[2-9][0-9])'; then
    info "Installing Python 3..."
    $PKG_INSTALL python3 python3-pip python3-venv
fi
PYTHON=$(command -v python3)
ok "Python: $($PYTHON --version)"

# ─── Create service user ──────────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    info "Creating service user '$SERVICE_USER'..."
    useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
    ok "User created"
fi

# ─── Copy application ─────────────────────────────────────────────────────────
info "Installing MailTool to $INSTALL_DIR..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$INSTALL_DIR"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='venv' --exclude='install.sh' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
ok "Files copied"

# ─── Python virtual environment + dependencies ────────────────────────────────
info "Creating virtual environment..."
$PYTHON -m venv "$INSTALL_DIR/venv"
VENV_PIP="$INSTALL_DIR/venv/bin/pip"
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet \
    fastapi uvicorn[standard] dnspython fpdf2 Pillow \
    python-whois python-multipart jinja2 aiofiles
ok "Python dependencies installed"

# ─── Systemd service ──────────────────────────────────────────────────────────
info "Creating systemd service..."
cat > /etc/systemd/system/mailtool.service <<EOF
[Unit]
Description=MailTool Email Security Checker
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m uvicorn main:app --host 127.0.0.1 --port ${LISTEN_PORT} --workers 2
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable mailtool
systemctl restart mailtool
ok "Service started (mailtool)"

# ─── Detect web server ────────────────────────────────────────────────────────
WEB_SERVER=""
command -v caddy  &>/dev/null && WEB_SERVER="caddy"
command -v nginx  &>/dev/null && [[ -z "$WEB_SERVER" ]] && WEB_SERVER="nginx"
command -v apache2 &>/dev/null && [[ -z "$WEB_SERVER" ]] && WEB_SERVER="apache2"

if [[ -z "$WEB_SERVER" ]]; then
    warn "No supported web server found. Installing Caddy (recommended)..."
    if [[ "$PKG_MGR" == "apt-get" ]]; then
        $PKG_INSTALL debian-keyring debian-archive-keyring apt-transport-https curl
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
            | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
            | tee /etc/apt/sources.list.d/caddy-stable.list
        apt-get update -qq
        apt-get install -y caddy
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        dnf install -y 'dnf-command(copr)'
        dnf copr enable -y @caddy/caddy
        dnf install -y caddy
    else
        warn "Could not auto-install Caddy. Please install a web server and proxy $DOMAIN -> 127.0.0.1:$LISTEN_PORT"
    fi
    WEB_SERVER="caddy"
fi
info "Web server: $WEB_SERVER"

# ─── Configure Caddy ──────────────────────────────────────────────────────────
if [[ "$WEB_SERVER" == "caddy" ]]; then
    CADDYFILE="/etc/caddy/Caddyfile"
    [[ -f "$CADDYFILE" ]] || CADDYFILE="/home/${SUDO_USER:-root}/Caddyfile"

    # Check if domain block already exists
    if grep -q "$DOMAIN" "$CADDYFILE" 2>/dev/null; then
        warn "Domain $DOMAIN already exists in $CADDYFILE — skipping (edit manually if needed)"
    else
        info "Adding $DOMAIN to $CADDYFILE..."
        cat >> "$CADDYFILE" <<EOF


${DOMAIN} {
    reverse_proxy 127.0.0.1:${LISTEN_PORT}
    encode gzip
    tls ${EMAIL}
}
EOF
        caddy reload --config "$CADDYFILE" 2>/dev/null || systemctl restart caddy
        ok "Caddy configured for $DOMAIN (TLS via Let's Encrypt)"
    fi

# ─── Configure nginx ──────────────────────────────────────────────────────────
elif [[ "$WEB_SERVER" == "nginx" ]]; then
    NGINX_CONF="/etc/nginx/sites-available/mailtool"
    NGINX_LINK="/etc/nginx/sites-enabled/mailtool"

    if [[ -f "$NGINX_CONF" ]]; then
        warn "$NGINX_CONF already exists — skipping (edit manually if needed)"
    else
        info "Writing nginx config..."
        cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:${LISTEN_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        client_max_body_size 10M;
    }
}
EOF
        ln -sf "$NGINX_CONF" "$NGINX_LINK"
        nginx -t && systemctl reload nginx
        ok "nginx configured for $DOMAIN"

        # Obtain Let's Encrypt certificate via certbot
        if command -v certbot &>/dev/null; then
            info "Obtaining TLS certificate from Let's Encrypt..."
            certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive --redirect
            ok "TLS certificate obtained and nginx reconfigured for HTTPS"
        else
            info "Installing certbot..."
            $PKG_INSTALL certbot python3-certbot-nginx
            certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive --redirect
            ok "TLS certificate obtained"
        fi
    fi

# ─── Configure Apache ─────────────────────────────────────────────────────────
elif [[ "$WEB_SERVER" == "apache2" ]]; then
    a2enmod proxy proxy_http ssl headers rewrite 2>/dev/null || true
    APACHE_CONF="/etc/apache2/sites-available/mailtool.conf"
    if [[ -f "$APACHE_CONF" ]]; then
        warn "$APACHE_CONF already exists — skipping"
    else
        cat > "$APACHE_CONF" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:${LISTEN_PORT}/
    ProxyPassReverse / http://127.0.0.1:${LISTEN_PORT}/
    RequestHeader set X-Forwarded-Proto "http"
</VirtualHost>
EOF
        a2ensite mailtool.conf
        systemctl reload apache2
        info "Installing certbot for Apache..."
        $PKG_INSTALL certbot python3-certbot-apache
        certbot --apache -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive --redirect
        ok "TLS certificate obtained"
    fi
fi

# ─── Open firewall ────────────────────────────────────────────────────────────
info "Opening firewall ports 80 and 443..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp  2>/dev/null || true
    ufw allow 443/tcp 2>/dev/null || true
    ok "ufw: ports 80 and 443 opened"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-service=http  2>/dev/null || true
    firewall-cmd --permanent --add-service=https 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    ok "firewalld: http/https services opened"
fi

# ─── Health check ─────────────────────────────────────────────────────────────
info "Waiting for service to start..."
sleep 3
if curl -sf "http://127.0.0.1:${LISTEN_PORT}/" -o /dev/null; then
    ok "MailTool is running on port $LISTEN_PORT"
else
    warn "Health check failed — check 'systemctl status mailtool' for errors"
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MailTool installed successfully!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "  URL:     ${CYAN}https://${DOMAIN}${NC}"
echo -e "  Service: ${CYAN}systemctl status mailtool${NC}"
echo -e "  Logs:    ${CYAN}journalctl -u mailtool -f${NC}"
echo ""
