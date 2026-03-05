#!/bin/bash
# Configure local development environment for MSSQL
# This script helps set up a local MSSQL instance for Sigil development

set -e

echo "=== Sigil MSSQL Development Setup ==="
echo

# Check OS
OS="$(uname -s)"
case "$OS" in
    Darwin*)    OS_TYPE="macOS";;
    Linux*)     OS_TYPE="Linux";;
    *)          OS_TYPE="Unknown";;
esac

echo "Detected OS: $OS_TYPE"

# Function to install ODBC driver on macOS
install_odbc_macos() {
    echo "Installing MSSQL ODBC Driver on macOS..."
    
    if command -v brew >/dev/null 2>&1; then
        echo "Using Homebrew to install ODBC driver..."
        brew tap microsoft/mssql-release https://github.com/Microsoft/homebrew-mssql-release
        brew update
        HOMEBREW_ACCEPT_EULA=Y brew install msodbcsql18 mssql-tools18
        echo "✅ ODBC Driver installed"
    else
        echo "❌ Homebrew not found. Please install Homebrew first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        return 1
    fi
}

# Function to install ODBC driver on Linux
install_odbc_linux() {
    echo "Installing MSSQL ODBC Driver on Linux..."
    
    # Add Microsoft repository
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
    
    # Detect Linux distro
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        UBUNTU_CODENAME=$(lsb_release -cs 2>/dev/null || echo "focal")
        curl -fsSL "https://packages.microsoft.com/config/ubuntu/20.04/prod.list" | sudo tee /etc/apt/sources.list.d/msprod.list
        sudo apt-get update
        sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18 unixodbc-dev
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        curl -fsSL https://packages.microsoft.com/config/rhel/8/prod.repo | sudo tee /etc/yum.repos.d/msprod.repo
        sudo yum remove -y unixODBC-utf16 unixODBC-utf16-devel
        sudo ACCEPT_EULA=Y yum install -y msodbcsql18 unixODBC-devel
    else
        echo "❌ Unsupported Linux distribution"
        return 1
    fi
    
    echo "✅ ODBC Driver installed"
}

# Function to start local SQL Server container
start_local_sqlserver() {
    echo "Starting local SQL Server container..."
    
    if ! command -v docker >/dev/null 2>&1; then
        echo "❌ Docker not found. Please install Docker first."
        return 1
    fi
    
    # Check if container already exists
    if docker ps -a | grep -q "sigil-mssql"; then
        echo "Existing sigil-mssql container found. Starting..."
        docker start sigil-mssql
    else
        echo "Creating new SQL Server container..."
        docker run -e "ACCEPT_EULA=Y" \
                   -e "MSSQL_SA_PASSWORD=SigilDev123!" \
                   -p 1433:1433 \
                   --name sigil-mssql \
                   --restart unless-stopped \
                   -d mcr.microsoft.com/mssql/server:2022-latest
        
        echo "Waiting for SQL Server to start..."
        sleep 30
    fi
    
    echo "✅ SQL Server container running"
    echo "   Connection: Server=localhost,1433;Database=master;User=sa;Password=SigilDev123!"
}

# Function to create Sigil database
create_sigil_database() {
    echo "Creating Sigil database..."
    
    # Create database using sqlcmd
    if command -v sqlcmd >/dev/null 2>&1; then
        sqlcmd -S localhost,1433 -U sa -P "SigilDev123!" -Q "
            IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'sigil')
            BEGIN
                CREATE DATABASE sigil
                PRINT 'Database sigil created successfully'
            END
            ELSE
            BEGIN
                PRINT 'Database sigil already exists'
            END
        "
    else
        echo "⚠️ sqlcmd not found. Creating database with Python..."
        python3 -c "
import pyodbc
try:
    conn = pyodbc.connect(
        'Driver={ODBC Driver 18 for SQL Server};'
        'Server=localhost,1433;'
        'Database=master;'
        'UID=sa;'
        'PWD=SigilDev123!;'
        'TrustServerCertificate=yes'
    )
    cursor = conn.cursor()
    cursor.execute(\"IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'sigil') CREATE DATABASE sigil\")
    conn.commit()
    print('✅ Database sigil created/verified')
except Exception as e:
    print(f'❌ Failed to create database: {e}')
"
    fi
}

# Function to create environment file
create_env_file() {
    echo "Creating development environment configuration..."
    
    ENV_FILE="api/.env.dev"
    
    cat > "$ENV_FILE" << 'EOF'
# Sigil API — Development Environment (MSSQL)
# Copy to api/.env for local development

# --- Application ---
SIGIL_DEBUG=true
SIGIL_LOG_LEVEL=DEBUG

# --- Server ---
SIGIL_HOST=0.0.0.0
SIGIL_PORT=8000

# --- CORS ---
SIGIL_CORS_ORIGINS=["http://localhost:3000","http://localhost:8000"]

# --- JWT / Auth ---
SIGIL_JWT_SECRET=dev-secret-change-in-production

# --- Database (MSSQL Local) ---
# Local SQL Server container connection
SIGIL_DATABASE_URL=Driver={ODBC Driver 18 for SQL Server};Server=localhost,1433;Database=sigil;UID=sa;PWD=SigilDev123!;TrustServerCertificate=yes

# --- Redis (optional) ---
# SIGIL_REDIS_URL=redis://localhost:6379

# --- Auth0 (for OAuth - optional in dev) ---
# SIGIL_AUTH0_DOMAIN=your-tenant.auth0.com
# SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai
# SIGIL_AUTH0_CLIENT_ID=your-client-id

# --- Anthropic API (for forge classification) ---
# SIGIL_ANTHROPIC_API_KEY=your-anthropic-key

EOF

    echo "✅ Created $ENV_FILE"
    echo "   Copy to api/.env: cp $ENV_FILE api/.env"
}

# Function to run basic schema
run_basic_schema() {
    echo "Running basic database schema..."
    
    python3 -c "
import sys
import asyncio
sys.path.append('.')

async def setup_schema():
    from api.database import db
    try:
        await db.connect()
        if not db.connected:
            print('❌ Database connection failed')
            return
        
        # Run basic schema
        with open('api/schema.sql', 'r') as f:
            schema_sql = f.read()
        
        # Split by GO statements
        statements = [s.strip() for s in schema_sql.split('GO') if s.strip()]
        
        for stmt in statements:
            if stmt and not stmt.startswith('--'):
                try:
                    await db.execute_raw_sql(stmt)
                except Exception as e:
                    print(f'Statement failed (may be normal): {e}')
        
        print('✅ Basic schema setup completed')
        
    except Exception as e:
        print(f'❌ Schema setup failed: {e}')
    finally:
        await db.disconnect()

asyncio.run(setup_schema())
"
}

# Main execution
echo "Choose setup options:"
echo "1. Install ODBC Driver"
echo "2. Start local SQL Server container"
echo "3. Create Sigil database"
echo "4. Create development environment file"
echo "5. Run basic database schema"
echo "6. All of the above"
echo

read -p "Enter your choice (1-6): " choice

case $choice in
    1)
        if [ "$OS_TYPE" = "macOS" ]; then
            install_odbc_macos
        elif [ "$OS_TYPE" = "Linux" ]; then
            install_odbc_linux
        else
            echo "❌ Unsupported OS"
            exit 1
        fi
        ;;
    2)
        start_local_sqlserver
        ;;
    3)
        create_sigil_database
        ;;
    4)
        create_env_file
        ;;
    5)
        run_basic_schema
        ;;
    6)
        echo "Running complete setup..."
        if [ "$OS_TYPE" = "macOS" ]; then
            install_odbc_macos
        elif [ "$OS_TYPE" = "Linux" ]; then
            install_odbc_linux
        else
            echo "❌ Unsupported OS"
            exit 1
        fi
        start_local_sqlserver
        create_sigil_database
        create_env_file
        run_basic_schema
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo
echo "=== Next Steps ==="
echo "1. Copy environment file: cp api/.env.dev api/.env"
echo "2. Install Python dependencies: pip install -r api/requirements.txt"
echo "3. Create forge tables: python scripts/setup_mssql_forge.py --create-tables"
echo "4. Process sample data: python scripts/setup_mssql_forge.py --process-data --limit 10"
echo "5. Start API: cd api && python -m uvicorn main:app --reload"
echo
echo "✅ MSSQL Development setup complete!"