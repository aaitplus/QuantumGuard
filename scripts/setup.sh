#!/bin/bash

# QuantumGuard Setup Script
# Automated installation of dependencies and tools for Linux, macOS, and Windows (WSL)

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
        elif command -v yum &> /dev/null; then
            OS="centos"
        elif command -v pacman &> /dev/null; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
    else
        OS="unknown"
    fi
    log_info "Detected OS: $OS"
}

# Check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Install package managers if needed
install_package_manager() {
    if [[ "$OS" == "ubuntu" ]]; then
        if ! command_exists apt-get; then
            log_error "apt-get not found. Please install apt first."
            exit 1
        fi
    elif [[ "$OS" == "centos" ]]; then
        if ! command_exists yum && ! command_exists dnf; then
            log_error "yum/dnf not found. Please install package manager first."
            exit 1
        fi
    elif [[ "$OS" == "arch" ]]; then
        if ! command_exists pacman; then
            log_error "pacman not found. Please install pacman first."
            exit 1
        fi
    elif [[ "$OS" == "macos" ]]; then
        if ! command_exists brew; then
            log_info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
    fi
}

# Install Python
install_python() {
    log_info "Installing Python 3.9+..."

    if command_exists python3 && python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"; then
        log_success "Python 3.9+ already installed"
        return
    fi

    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        centos)
            sudo yum install -y python39 python39-pip
            ;;
        arch)
            sudo pacman -S python python-pip
            ;;
        macos)
            brew install python@3.9
            ;;
        windows)
            log_warning "Please install Python manually from https://python.org"
            log_warning "Ensure Python is added to PATH"
            return
            ;;
    esac

    if command_exists python3; then
        log_success "Python installed successfully"
    else
        log_error "Failed to install Python"
        exit 1
    fi
}

# Install Node.js
install_nodejs() {
    log_info "Installing Node.js 18+..."

    if command_exists node && node -v | grep -q "v18\|v19\|v20"; then
        log_success "Node.js 18+ already installed"
        return
    fi

    case $OS in
        ubuntu)
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt-get install -y nodejs
            ;;
        centos)
            curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
            sudo yum install -y nodejs
            ;;
        arch)
            sudo pacman -S nodejs npm
            ;;
        macos)
            brew install node@18
            ;;
        windows)
            log_warning "Please install Node.js manually from https://nodejs.org"
            return
            ;;
    esac

    if command_exists node; then
        log_success "Node.js installed successfully"
    else
        log_error "Failed to install Node.js"
        exit 1
    fi
}

# Install Docker
install_docker() {
    log_info "Installing Docker..."

    if command_exists docker && docker --version &> /dev/null; then
        log_success "Docker already installed"
        return
    fi

    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io
            sudo usermod -aG docker $USER
            ;;
        centos)
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io
            sudo systemctl start docker
            sudo usermod -aG docker $USER
            ;;
        arch)
            sudo pacman -S docker
            sudo usermod -aG docker $USER
            ;;
        macos)
            brew install --cask docker
            ;;
        windows)
            log_warning "Please install Docker Desktop manually from https://docker.com"
            log_warning "For WSL2, ensure Docker Desktop is configured for WSL2"
            return
            ;;
    esac

    if command_exists docker; then
        log_success "Docker installed successfully"
        log_warning "You may need to log out and back in for Docker group changes to take effect"
    else
        log_error "Failed to install Docker"
        exit 1
    fi
}

# Install security scanning tools
install_security_tools() {
    log_info "Installing security scanning tools..."

    # Install Semgrep
    if ! command_exists semgrep; then
        log_info "Installing Semgrep..."
        if command_exists pip3; then
            pip3 install semgrep
        else
            log_error "pip3 not found. Please install Python first."
            return
        fi
    else
        log_success "Semgrep already installed"
    fi

    # Install Trivy
    if ! command_exists trivy; then
        log_info "Installing Trivy..."
        case $OS in
            ubuntu|centos)
                sudo apt-get update
                sudo apt-get install -y wget apt-transport-https gnupg lsb-release
                wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
                sudo apt-get update
                sudo apt-get install -y trivy
                ;;
            arch)
                sudo pacman -S trivy
                ;;
            macos)
                brew install trivy
                ;;
            windows)
                log_warning "Please install Trivy manually from https://aquasecurity.github.io/trivy/"
                ;;
        esac
    else
        log_success "Trivy already installed"
    fi

    # Install tfsec
    if ! command_exists tfsec; then
        log_info "Installing tfsec..."
        case $OS in
            ubuntu|centos|arch)
                curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install.sh | bash
                ;;
            macos)
                brew install tfsec
                ;;
            windows)
                log_warning "Please install tfsec manually from https://aquasecurity.github.io/tfsec/"
                ;;
        esac
    else
        log_success "tfsec already installed"
    fi
}

# Install kubectl
install_kubectl() {
    log_info "Installing kubectl..."

    if command_exists kubectl; then
        log_success "kubectl already installed"
        return
    fi

    case $OS in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y apt-transport-https ca-certificates curl
            sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
            echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
            sudo apt-get update
            sudo apt-get install -y kubectl
            ;;
        centos)
            cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
            sudo yum install -y kubectl
            ;;
        arch)
            sudo pacman -S kubectl
            ;;
        macos)
            brew install kubectl
            ;;
        windows)
            log_warning "Please install kubectl manually from https://kubernetes.io/docs/tasks/tools/"
            ;;
    esac

    if command_exists kubectl; then
        log_success "kubectl installed successfully"
    else
        log_error "Failed to install kubectl"
    fi
}

# Install Terraform
install_terraform() {
    log_info "Installing Terraform..."

    if command_exists terraform; then
        log_success "Terraform already installed"
        return
    fi

    case $OS in
        ubuntu)
            sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
            wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
            sudo apt-get update && sudo apt-get install -y terraform
            ;;
        centos)
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
            sudo yum -y install terraform
            ;;
        arch)
            sudo pacman -S terraform
            ;;
        macos)
            brew tap hashicorp/tap
            brew install hashicorp/tap/terraform
            ;;
        windows)
            log_warning "Please install Terraform manually from https://terraform.io"
            ;;
    esac

    if command_exists terraform; then
        log_success "Terraform installed successfully"
    else
        log_error "Failed to install Terraform"
    fi
}

# Setup Python virtual environment and install dependencies
setup_python_env() {
    log_info "Setting up Python virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi

    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt

    log_success "Python environment setup complete"
}

# Create necessary directories
create_directories() {
    log_info "Creating project directories..."

    directories=("data" "reports" "dashboard/static/css" "dashboard/static/js" "k8s")

    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done

    log_success "Directory structure created"
}

# Main setup function
main() {
    log_info "Starting QuantumGuard setup..."

    detect_os
    install_package_manager

    install_python
    install_nodejs
    install_docker
    install_security_tools
    install_kubectl
    install_terraform

    create_directories
    setup_python_env

    log_success "QuantumGuard setup completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Log out and back in (or restart) for Docker group changes"
    log_info "2. Run: source venv/bin/activate"
    log_info "3. Start the dashboard: python dashboard/app.py"
    log_info "4. Open browser to http://localhost:5000"
    log_info ""
    log_info "For Windows users, ensure WSL2 and Docker Desktop are properly configured."
}

# Run main function
main "$@"
