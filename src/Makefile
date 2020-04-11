#master makefile, because all of the other build systems are horrible
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

wasm:
	