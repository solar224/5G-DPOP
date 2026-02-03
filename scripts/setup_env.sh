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
        tshark \
        dwarves  # Required for pahole - generates BTF for kernel modules
    
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

# Setup gtp5g module with BTF support for eBPF
# This is required for eBPF fentry/fexit to attach to gtp5g functions
setup_gtp5g_btf() {
    echo ""
    echo "Setting up gtp5g module with BTF support..."
    
    # Default gtp5g source path
    GTP5G_SRC="${GTP5G_PATH:-$HOME/gtp5g}"
    
    if [ ! -d "$GTP5G_SRC" ]; then
        print_warning "gtp5g source not found at $GTP5G_SRC"
        print_warning "Clone it with: git clone https://github.com/free5gc/gtp5g.git ~/gtp5g"
        return 1
    fi
    
    # Check if gtp5g module is loaded and has BTF
    if [ -f "/sys/kernel/btf/gtp5g" ]; then
        print_status "gtp5g module already has BTF support"
        return 0
    fi
    
    # Check if pahole is available
    if ! command -v pahole &> /dev/null; then
        print_error "pahole not found. Install with: sudo apt-get install dwarves"
        return 1
    fi
    
    print_warning "gtp5g module needs BTF for eBPF support. Generating..."
    
    cd "$GTP5G_SRC"
    
    # Build gtp5g if needed
    if [ ! -f "gtp5g.ko" ]; then
        print_warning "Building gtp5g module..."
        make clean
        make
    fi
    
    # Generate BTF using pahole
    print_warning "Generating BTF for gtp5g.ko using pahole..."
    BTF_FILE="/tmp/gtp5g_$$.btf"
    
    if pahole --btf_encode_detached="$BTF_FILE" --btf_base=/sys/kernel/btf/vmlinux gtp5g.ko 2>/dev/null; then
        # Embed BTF into module
        if objcopy --add-section .BTF="$BTF_FILE" --set-section-flags .BTF=alloc,readonly gtp5g.ko gtp5g_btf.ko 2>/dev/null; then
            print_status "BTF generated and embedded into gtp5g_btf.ko"
            
            # Unload old module if loaded
            if lsmod | grep -q gtp5g; then
                print_warning "Unloading existing gtp5g module..."
                sudo rmmod gtp5g 2>/dev/null || true
            fi
            
            # Load new module with BTF
            print_warning "Loading gtp5g_btf.ko..."
            sudo insmod gtp5g_btf.ko
            
            # Verify BTF is available
            if [ -f "/sys/kernel/btf/gtp5g" ]; then
                print_status "gtp5g module loaded with BTF support!"
            else
                print_error "BTF not available after loading module"
                return 1
            fi
        else
            print_error "Failed to embed BTF into gtp5g.ko"
            return 1
        fi
        
        rm -f "$BTF_FILE"
    else
        print_error "Failed to generate BTF using pahole"
        print_warning "Make sure gtp5g.ko was built with debug info"
        return 1
    fi
    
    cd - > /dev/null
    
    # Verify symbols are available
    if sudo cat /proc/kallsyms | grep -q "gtp5g_encap_recv"; then
        print_status "gtp5g symbols are available for eBPF hooking"
    else
        print_warning "gtp5g symbols not found. Check if module is loaded correctly."
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
    setup_gtp5g_btf
    
    echo ""
    echo "======================================"
    echo "Setup Complete!"
    echo "======================================"
    echo ""
    echo "Next steps:"
    echo "  1. Source your bashrc: source ~/.bashrc"
    echo "  2. Start free5gc: cd ~/free5gc-compose && docker compose -f docker-compose-ulcl.yaml up -d"
    echo "  3. Build the project: make all"
    echo "  4. Start observability stack: make compose-up"
    echo "  5. Run agent: sudo ./bin/agent"
    echo ""
    echo "Note: gtp5g module with BTF support has been configured."
    echo "      If you restart the system, run: scripts/setup_env.sh --gtp5g-only"
    echo ""
}

# Handle command line arguments
case "${1:-}" in
    --gtp5g-only)
        echo "Setting up gtp5g BTF only..."
        setup_gtp5g_btf
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --gtp5g-only    Only setup gtp5g module with BTF (use after system restart)"
        echo "  --help, -h      Show this help message"
        echo ""
        echo "Without options, runs full environment setup."
        ;;
    *)
        main "$@"
        ;;
esac
