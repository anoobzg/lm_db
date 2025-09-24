#include "lm/kernel/lmuserdb.h"

int main() 
{
    lmdb::LMUserDB userDB("lmuser.db");
    userDB.print();
    userDB.print("username = 'bob'");

    userDB.set_password("alice", "newpassword");
    userDB.print();

    userDB.set_password("bob", "newpassword");
    userDB.print();
    return 0;
}