#master makefile, because other build systems are horrible
SHELL = /bin/bash
default:
	idf.py build
flash:
	idf.py flash
monitor: flash
	idf.py monitor
reflash:
	idf.py erase_flash
	idf.py flash
remonitor: reflash
	idf.py monitor