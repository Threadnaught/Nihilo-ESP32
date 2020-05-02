root-opt.wasm: root.cpp api.syms ../include/api.h
	wasic++ -Os -z stack-size=4096 -Wl,--initial-memory=65536 -Wl,--strip-all -Wl,--no-entry -Wl,--allow-undefined-file=api.syms -o root.wasm root.cpp
	wasm-opt -Oz root.wasm -o root-opt.wasm
	xxd -i root-opt.wasm > ../include/root.wasm.h
clean:
	rm *.wasm
	rm ../include/*.wasm.h