#include <iostream>
#include <memory>
#include "User.h"

int main(int argc, char* argv[]) {
    std::unique_ptr<User> user(new User());
    user -> start();
}