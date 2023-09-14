#!/bin/bash

set -e
set -x

./f5-tmsh-generator.py config/bigip-v13-config-clone-pool.1.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13-config-clone-pool.2.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13-f5config.1.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13-f5config.2.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13-f5config.3.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13-validation-question-1.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v13-validation-question-2.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v15.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v11.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/bigip-v10.running-config config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/f5config.0 config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/f5config.1 config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/f5config.2 config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/f5config.3 config/app/request-vs-not-exist-net-exist-http.txt
./f5-tmsh-generator.py config/f5config.2 config/app/request-net.txt
./f5-tmsh-generator.py config/f5config.2 config/app/request-net-empty.txt
./f5-tmsh-generator.py config/f5config.2 config/app/request-vs-exist-pool-not-exist-snat-not-exist.txt
./f5-tmsh-generator.py config/f5config.2 config/app/request-vs-exist-pool-not-exist-snat-exist.txt
./f5-tmsh-generator.py config/f5config.3 config/app/request-vs-exist-pool-exist-snat-not-exist.txt
./f5-tmsh-generator.py config/f5config.3 config/app/request-vs-exist-pool-exist-snat-exist.txt
./f5-tmsh-generator.py config/f5config.3 config/app/request-net-not-exist-vs-not-exist.txt
