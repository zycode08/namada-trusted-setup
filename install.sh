#!/bin/sh
# shellcheck shell=dash

# # This is just a little script that can be downloaded from the internet to
# install Anoma Trusted Setup bianries. It just does platform detection,
# downloads and install the correct binaries.

set -u

LAST_BINARY_VERSION="1.0.0-beta.3"
BINARY_NAME="namada-ts"
BINARY_FOLDER="$HOME/.namada-ts"
BINARY_PATH="$BINARY_FOLDER/$BINARY_NAME"

OS_TYPE=$(uname -s)
ARCHITECTURE=$(uname -m)

BINARY_EXIST_CHECK=$(command -v $BINARY_NAME &>/dev/null)

if [ "$EUID" -eq 0 ]; then
    echo "Do not run as sudo."
    exit
fi

if ! $BINARY_EXIST_CHECK; then
    CURRENT_BINARY_VERSION_CHECK=$($BINARY_NAME --version)
    if [[ "$BINARY_NAME $LAST_BINARY_VERSION" == "$CURRENT_BINARY_VERSION_CHECK" ]]; then
        echo "Your binaries are up to date!"
    else
        echo "Removing old binary..."
        rm $BINARY_PATH
        echo "Downloading newer binary for ${OS_TYPE}/${ARCHITECTURE}..."

        if [[ "$OS_TYPE" == "Darwin" && "$ARCHITECTURE" == "x86_64" ]]; then
            curl -s https://github.com/anoma/namada-trusted-setup/releases/download/v${LAST_BINARY_VERSION}/${BINARY_NAME}-macos-v${LAST_BINARY_VERSION} -L -o $BINARY_PATH
        elif [[ "$OS_TYPE" == "Linux" && "$ARCHITECTURE" == "x86_64" ]]; then
            curl -s https://github.com/anoma/namada-trusted-setup/releases/download/v${LAST_BINARY_VERSION}/${BINARY_NAME}-linux-v${LAST_BINARY_VERSION} -L -o $BINARY_PATH
        else
            echo "No binary for ${OS_TYPE}/${ARCHITECTURE}."
            echo "You should clone the repository and build from source."
            exit
        fi
        echo "Done dowloading binary in $BINARY_PATH."
        echo "Your should export the binary to \$PATH by running:"
        echo "   export PATH=\$PATH:~/.namada-ts"
        chmod +x "$BINARY_FOLDER/$BINARY_NAME"
    fi
else
    echo "Creating binary folder..."
    mkdir -p $BINARY_FOLDER
    echo "Downloading new binary for ${OS_TYPE}/${ARCHITECTURE}..."

    if [[ "$OS_TYPE" == "Darwin" && "$ARCHITECTURE" == "x86_64" ]]; then
        curl -s https://github.com/anoma/namada-trusted-setup/releases/download/v${LAST_BINARY_VERSION}/${BINARY_NAME}-macos-v${LAST_BINARY_VERSION} -L -o $BINARY_PATH
    elif [[ "$OS_TYPE" == "Linux" && "$ARCHITECTURE" == "x86_64" ]]; then
        curl -s https://github.com/anoma/namada-trusted-setup/releases/download/v${LAST_BINARY_VERSION}/${BINARY_NAME}-linux-v${LAST_BINARY_VERSION} -L -o $BINARY_PATH
    else
        echo "No binary for ${OS_TYPE}/${ARCHITECTURE}."
        echo "You should clone the repository and build from source. Check the docs here: https://github.com/anoma/namada-trusted-setup#building-and-contributing-from-source."
        exit
    fi
    chmod +x "$BINARY_FOLDER/$BINARY_NAME"
    echo "Done dowloading binary in $BINARY_PATH."
    echo "Your should export the binary to \$PATH by running:"
    echo "   export PATH=\$PATH:~/.namada-ts"
fi
