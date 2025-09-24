#include "lm/kernel/lmuserdb.h"

#include "sqlite.hpp"
#include "dbng.hpp"

struct db_User
{
    std::string username;
    std::string password;
    std::string description;
    int id;
};
REGISTER_AUTO_KEY(db_User, id)
YLT_REFL(db_User, id, username, password, description)

namespace lmdb {
    struct LMUserDBImpl
    {
        ormpp::dbng<ormpp::sqlite> sqlite;
    };

    LMUserDB::LMUserDB(const std::string& db_path) 
        : impl(new LMUserDBImpl()) 
    {
        impl->sqlite.connect(db_path);
    }   

    LMUserDB::~LMUserDB() 
    { 
        delete impl; 
        impl = nullptr;
    }

    void LMUserDB::clear_users()
    {
        ormpp_auto_key user_key{"id"};                     
        ormpp_unique user_unique{{"username"}};

        impl->sqlite.create_datatable<db_User>(user_key, user_unique);
        impl->sqlite.delete_records<db_User>();
    }

    void LMUserDB::remove_user(const std::string& user_name)
    {

    }

    bool LMUserDB::add_user(const std::string& user_name, const std::string& description)
    {
        auto vec = impl->sqlite.query<db_User>("username='" + user_name + "'");

        assert(vec.size() <= 1);
        if (vec.size() == 1) {
            return false;
        }        
        impl->sqlite.insert<db_User>({user_name, "", description});
        return true;
    }

    bool LMUserDB::set_password(const std::string& user_name, const std::string& new_password)
    {
        auto users = impl->sqlite.query_s<db_User>("username = ?", user_name);
        assert(users.size() <= 1);
        if (users.size() == 1) {
            db_User u = users[0];
            u.password = new_password;
            impl->sqlite.update(u);
            return true;
        }
        return false;
    }
        
    bool LMUserDB::get_password(const std::string& user_name, std::string& out_password)
    {
        auto users = impl->sqlite.query_s<db_User>("username = ?", user_name);
        assert(users.size() <= 1);
        if (users.size() == 1) {
            out_password = users[0].password;
            return true;
        }
        return false;
    }

    void LMUserDB::print(const std::string& query)
    {
        std::cout << "print start ---------------- \n";
        auto vec = impl->sqlite.query<db_User>(query);
        for (const auto& user : vec) {
            std::cout << user.id << ", " << user.username << ", " << user.password << ", " << user.description << "\n";
        }

        std::cout << "print end ------------------\n";
        std::cout << std::endl;
    }
}