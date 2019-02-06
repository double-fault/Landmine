/*
 * landmine.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 22nd January 2019.
 * 
 *
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#include "crow.h"

class Landmine {
    public:
        Landmine(int app_port);
        void init(void);
    private:
        crow::SimpleApp app;
        int port;
}

Landmine::Landmine(int app_port) {
    port = app_port;
}

void Landmine::init(void) {
    crow::logger:setLogLevel(crow::LogLevel::Debug); 

