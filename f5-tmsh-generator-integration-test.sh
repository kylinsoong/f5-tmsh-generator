#!/bin/bash

set -e
set -x

./f5-tmsh-generator-v2.py config/bigip-v13-config-clone-pool.1.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-config-clone-pool.2.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-f5config.1.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-f5config.2.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-f5config.3.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-validation-question-1.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v13-validation-question-2.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v15.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v11.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/bigip-v10.running-config test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/f5config.0 test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/f5config.1 test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-net.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-net-empty.txt
./f5-tmsh-generator-v2.py config/f5config.2  test/request-vs-exist-pool-not-exist-snat-not-exist.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-vs-exist-pool-not-exist-snat-exist.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-vs-exist-pool-exist-snat-not-exist.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-vs-exist-pool-exist-snat-exist.txt
./f5-tmsh-generator-v2.py config/f5config.2 test/request-vs-not-exist-net-exist.txt
./f5-tmsh-generator-v2.py config/f5config.3 test/request-net-not-exist-vs-not-exist.txt
