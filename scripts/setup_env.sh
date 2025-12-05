#!/bin/bash
# setup_env.sh - Install development dependencies for 5G-DPOP
# Tested on Ubuntu 25.04 with kernel 6.14

set -e

echo "======================================"
echo "5G-DPOP Environment Setup"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running as root for some operations
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_warning "Some operations require sudo. You may be prompted for password."
    fi
}

# Install system dependencies
install_system_deps() {
    echo ""
    echo "Installing system dependencies..."
    
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        clang \
        llvm \
        libbpf-dev \
        linux-headers-$(uname -r) \
        libelf-dev \
        libpcap-dev \
        pkg-config \
        bpftool \
        bpftrace \
        tcpdump \
        wireshark-common \
        tshark
    
    print_status "System dependencies installed"
}

# Install Go (if not present or wrong version)
install_go() {
    echo ""
    echo "Checking Go installation..."
    
    GO_VERSION="1.21.5"
    
    if command -v go &> /dev/null; then
        CURRENT_VERSION=$(go version | grep -oP '\d+\.\d+\.\d+')
        if [[ "$(printf '%s\n' "1.21.0" "$CURRENT_VERSION" | sort -V | head -n1)" == "1.21.0" ]]; then
            print_status "Go $CURRENT_VERSION is already installed"
            return
        fi
    fi
    
    print_warning "Installing Go $GO_VERSION..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add to PATH if not already
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
        print_warning "Added Go to ~/.bashrc. Run 'source ~/.bashrc' after setup completes."
    fi
    export PATH=$PATH:/usr/local/go/bin
    print_status "Go $GO_VERSION installed"
}

# Install Node.js (if not present)
install_nodejs() {
    echo ""
    echo "Checking Node.js installation..."
    
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v | grep -oP '\d+' | head -1)
        if [ "$NODE_VERSION" -ge 18 ]; then
            print_status "Node.js $(node -v) is already installed"
            return
        fi
    fi
    
    print_warning "Installing Node.js 18 LTS..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    print_status "Node.js installed"
}

# Install Docker (if not present)
install_docker() {
    echo ""
    echo "Checking Docker installation..."
    
    if command -v docker &> /dev/null; then
        print_status "Docker is already installed"
        return
    fi
    
    print_warning "Installing Docker..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sudo sh /tmp/get-docker.sh
    sudo usermod -aG docker $USER
    rm /tmp/get-docker.sh
    
    print_status "Docker installed (you may need to re-login for group changes)"
}

# Install Go tools
install_go_tools() {
    echo ""
    echo "Installing Go development tools..."
    
    export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin
    
    # bpf2go for generating Go bindings
    go install github.com/cilium/ebpf/cmd/bpf2go@latest
    
    print_status "Go tools installed"
}

# Generate vmlinux.h for eBPF CO-RE
generate_vmlinux() {
    echo ""
    echo "Generating vmlinux.h for eBPF CO-RE..."
    
    VMLINUX_DIR="internal/ebpf/bpf"
    mkdir -p "$VMLINUX_DIR"
    
    if [ -f "/sys/kernel/btf/vmlinux" ]; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_DIR/vmlinux.h"
        print_status "vmlinux.h generated from running kernel"
    else
        print_warning "BTF not available. Downloading pre-generated vmlinux.h..."
        # Fallback: use libbpf's vmlinux.h
        if [ -f "/usr/include/bpf/vmlinux.h" ]; then
            cp /usr/include/bpf/vmlinux.h "$VMLINUX_DIR/"
        else
            print_error "Could not generate vmlinux.h. eBPF CO-RE may not work."
        fi
    fi
}

# Verify gtp5g module
verify_gtp5g() {
    echo ""
    echo "Verifying gtp5g kernel module..."
    
    if lsmod | grep -q gtp5g; then
        print_status "gtp5g module is loaded"
    else
        print_warning "gtp5g module is not loaded. Load it with: sudo insmod /path/to/gtp5g.ko"
    fi
    
    # Check if symbols are available
    if sudo cat /proc/kallsyms | grep -q "gtp5g_encap_recv"; then
        print_status "gtp5g symbols are available for eBPF hooking"
    else
        print_warning "gtp5g symbols not found. Make sure the module is loaded."
    fi
}

# Create directory structure
create_directories() {
    echo ""
    echo "Creating project directory structure..."
    
    mkdir -p cmd/agent
    mkdir -p cmd/api-server
    mkdir -p cmd/fault-injector
    mkdir -p internal/ebpf/bpf
    mkdir -p internal/pfcp
    mkdir -p internal/metrics
    mkdir -p internal/api
    mkdir -p web/src/components
    mkdir -p web/src/hooks
    mkdir -p web/src/services
    mkdir -p web/public
    mkdir -p deployments
    mkdir -p scripts
    mkdir -p test/integration
    mkdir -p test/e2e
    mkdir -p docs
    mkdir -p bin
    
    print_status "Directory structure created"
}

# Main
main() {
    check_root
    install_system_deps
    install_go
    install_nodejs
    install_docker
    install_go_tools
    create_directories
    generate_vmlinux
    verify_gtp5g
    
    echo ""
    echo "======================================"
    echo "Setup Complete!"
    echo "======================================"
    echo ""
    echo "Next steps:"
    echo "  1. Source your bashrc: source ~/.bashrc"
    echo "  2. Make sure gtp5g is loaded: sudo insmod ~/gtp5g/gtp5g.ko"
    echo "  3. Build the project: make all"
    echo "  4. Start observability stack: make compose-up"
    echo "  5. Run agent: sudo ./bin/agent"
    echo ""
}

main "$@"
