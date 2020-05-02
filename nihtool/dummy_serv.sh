for x in "aaa" "bbb" "ccc" "ddd"; do
	curl -d "$x:`openssl rand -hex 32 | tr a-z A-Z`" 127.0.0.1
done
