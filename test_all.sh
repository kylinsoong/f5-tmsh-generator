#!/bin/bash

./f5-tmsh-generator-v2.py config/bigip-v13-config-clone-pool.1.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-config-clone-pool.1.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-config-clone-pool.2.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v15.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v11.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v10.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-vs-not-exist-net-exist-http.txt
