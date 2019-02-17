all:
	g++ -std=c++14 src/*.cpp -lboost_system -lpthread -lboost_regex -lfaupl -lfmt -o landmine
