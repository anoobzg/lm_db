#include "lm/kernel/lmuserdb.h"

int main() 
{
    lmdb::LMUserDB userDB("lmuser.db");

    userDB.clear_users();
    userDB.add_user("alice", "Alice's account");
    userDB.set_password("alice", "password123");
    userDB.add_user("bob", "Bob's account");
    userDB.set_password("bob", "securepass");
    userDB.add_user("charlie", "Charlie's account");
    userDB.set_password("charlie", "charliepwd");

    userDB.add_user("bob", "Bob's account");
    userDB.set_password("bob1", "newpass");
    return 0;
}