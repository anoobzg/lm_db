#pragma once
#include "lm/export.h"
#include <string>

namespace lmdb 
{
    struct LMUserDBImpl;
    class LM_DB_API LMUserDB
    {
    public:
        LMUserDB(const std::string& db_path);
        ~LMUserDB();

        bool add_user(const std::string& user_name, const std::string& description = "");

        void clear_users();
        void remove_user(const std::string& user_name);

        bool set_password(const std::string& user_name, const std::string& new_password);
        
        bool get_password(const std::string& user_name, std::string& out_password);

        void print(const std::string& query = "");
    protected:
        LMUserDBImpl* impl;
    };
}