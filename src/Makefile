#master makefile, because all of the other build systems are horrible
default: allfiles
	idf.py build
flash: allfiles
	idf.py flash
monitor: flash
	idf.py monitor
reflash: allfiles
	idf.py erase_flash
	idf.py flash
remonitor: reflash
	idf.py monitor

wasm/wasm-opt.wasm: wasm/root.cpp
	make -C wasm

#target to make sensitive to all files:
allfiles: wasm/wasm-opt.wasm include/root.wasm.h main/*.cpp