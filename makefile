all:
	clang++ -std=c++14 -fsanitize=address -O1 -fno-omit-frame-pointer -g -rdynamic src/*.cpp -lboost_regex -lfaupl -lfmt -o landmine -ferror-limit=10000
