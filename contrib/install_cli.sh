 #!/usr/bin/env bash

 # Execute this file to install the neurai cli tools into your path on OS X

 CURRENT_LOC="$( cd "$(dirname "$0")" ; pwd -P )"
 LOCATION=${CURRENT_LOC%Neurai-Qt.app*}

 # Ensure that the directory to symlink to exists
 sudo mkdir -p /usr/local/bin

 # Create symlinks to the cli tools
 sudo ln -s ${LOCATION}/Neurai-Qt.app/Contents/MacOS/neuraid /usr/local/bin/neuraid
 sudo ln -s ${LOCATION}/Neurai-Qt.app/Contents/MacOS/neurai-cli /usr/local/bin/neurai-cli
