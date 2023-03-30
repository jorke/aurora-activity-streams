

#!/bin/bash
set -eo pipefail
mkdir -p ../js-layer/lib/nodejs
rm -rf node_modules ../js-layer/lib/nodejs/node_modules
npm install --production
mv node_modules ../js-layer/lib/nodejs/