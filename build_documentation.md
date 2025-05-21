# Build Documentation

This document outlines the step-by-step process for setting up and building this project on an Ubuntu 24.04 virtual machine.

## 1. Prerequisites

Ensure the system is up to date and required base packages are installed:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  libssl-dev \
  libcurl4-openssl-dev \
  libexpat1-dev \
  zlib1g-dev \
  pkg-config
  libncurses5-dev \
  libncursesw5-dev
````

## 2. Install and Configure `pyenv`

Use `pyenv` to manage Python versions and install Python 2.7.18 for OpenWrt build tools.

1. **Install `pyenv`**:

   ```bash
   curl https://pyenv.run | bash
   ```

2. **Add `pyenv` to shell configuration** (in `~/.bashrc` or `~/.zshrc`):

   ```bash
   export PATH="$HOME/.pyenv/bin:$PATH"
   eval "$(pyenv init --path)"
   eval "$(pyenv init -)"
   eval "$(pyenv virtualenv-init -)"
   ```

3. **Reload shell**:

   ```bash
   source ~/.bashrc
   ```

4. **Install Python 2.7.18**:

   ```bash
   pyenv install 2.7.18
   ```

5. **Set local Python version** in the OpenWrt directory:

   ```bash
   cd ~/OpenWrt/openwrt-18.06.2
   pyenv local 2.7.18
   ```

6. **Verify**:

   ```bash
   python --version    # Should show Python 2.7.18
   python2 --version   # Should show Python 2.7.18
   ```

## 3. Grant Execute Permissions

Make build scripts executable:

```bash
cd ~/OpenWrt/openwrt-18.06.2
sudo chmod +x scripts/*
```

Make SCons helper scripts executable:

```bash
find tools/scons -type f -name "*.sh" -exec chmod +x {} \;
```

## 4. Update and Install Feeds

Fetch and install all package feeds:

```bash
./scripts/feeds update -a
./scripts/feeds install -a
```

## 5. Configure the Build

Launch the configuration menu to select target options and packages:

```bash
make menuconfig
```

When the configuration menu open, select Save > Ok > Exit >Exit

## 7. Build 

```bash
make -j4   # replace 4 with the number of logical CPU cores available
```

