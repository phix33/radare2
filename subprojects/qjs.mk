# This file is autogenerated by acr-wrap

WRAP_wrap_git_url:=https://github.com/quickjs-ng/quickjs
WRAP_wrap_git_revision:=7e292050a21d3dd5076f70116ae95cc5200c40c1
WRAP_wrap_git_directory:=qjs
WRAP_wrap_git_patch_directory:=qjs
WRAP_wrap_git_depth:=1

qjs_all: qjs
	@echo "Nothing to do"

qjs:
	git clone --no-checkout --depth=1 https://github.com/quickjs-ng/quickjs qjs
	cd qjs && git fetch --depth=1 origin 7e292050a21d3dd5076f70116ae95cc5200c40c1
	cd qjs && git checkout
	cp -f packagefiles/qjs/* qjs

qjs_clean:
	rm -rf qjs
