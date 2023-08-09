#!/bin/bash

set -e
set -x

./f5-tmsh-generator.py config/f5config.2 test/request-net.txt 
./f5-tmsh-generator-v2.py config/f5config.2 test/request-net.txt 
echo 

./f5-tmsh-generator.py config/f5config.2 test/request-net-empty.txt 
./f5-tmsh-generator-v2.py config/f5config.2 test/request-net-empty.txt 
echo

./f5-tmsh-generator.py  config/f5config.2  test/request-vs-exist-pool-not-exist-snat-not-exist.txt
./f5-tmsh-generator-v2.py  config/f5config.2  test/request-vs-exist-pool-not-exist-snat-not-exist.txt
echo

./f5-tmsh-generator.py config/f5config.2 test/request-vs-exist-pool-not-exist-snat-exist.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-vs-exist-pool-not-exist-snat-exist.txt
echo

./f5-tmsh-generator.py config/f5config.3 test/request-vs-exist-pool-exist-snat-not-exist.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-vs-exist-pool-exist-snat-not-exist.txt
echo

./f5-tmsh-generator.py config/f5config.3 test/request-vs-exist-pool-exist-snat-exist.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-vs-exist-pool-exist-snat-exist.txt
echo

./f5-tmsh-generator.py config/f5config.2 test/request-vs-not-exist-net-exist.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-vs-not-exist-net-exist.txt
echo

./f5-tmsh-generator.py config/f5config.3 test/request-net-not-exist-vs-not-exist.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-net-not-exist-vs-not-exist.txt





