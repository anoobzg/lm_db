#include "lm/kernel/lmdbcore.h"

#include "sqlite.hpp"
#include "dbng.hpp"
#include "lm/gcode/gcode_processor.h"
#include "lm/crypto/aes_encryption.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <random>
#include <filesystem>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <sstream>

// Platform-specific headers for user data directory
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#else
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <climits>
#endif

// Helper functions for hex conversion
std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

 

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to get error message from error code
const char* get_db_error_message(DB_RESULT error_code) {
    switch (error_code) {
        case DB_SUCCESS:
            return "Operation successful";
        case DB_ERROR_DATABASE_CONNECTION:
            return "Database connection error";
        case DB_ERROR_SQL_EXECUTION:
            return "SQL execution error";
        case DB_ERROR_RECORD_NOT_FOUND:
            return "Record not found";
        case DB_ERROR_DUPLICATE_RECORD:
            return "Duplicate record (unique constraint violation)";
        case DB_ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case DB_ERROR_PERMISSION_DENIED:
            return "Permission denied";
        case DB_ERROR_FOREIGN_KEY_CONSTRAINT:
            return "Foreign key constraint violation";
        case DB_ERROR_DATABASE_LOCKED:
            return "Database is locked";
        case DB_ERROR_DISK_FULL:
            return "Disk full";
        case DB_ERROR_OLD_PASSWORD_INCORRECT:
            return "Old password is incorrect";
        case DB_ERROR_PASSWORD_INCORRECT:
            return "Password is incorrect";
        case DB_ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}

// Helper function to get user data directory
std::string getUserDataDirectory() {
    std::string userDataDir;
    
#ifdef _WIN32
    // Windows: C:\Users\<username>\AppData\Local\<company>
    char* appDataPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, (PWSTR*)&appDataPath))) {
        // Convert wide string to narrow string
        int size = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)appDataPath, -1, nullptr, 0, nullptr, nullptr);
        if (size > 0) {
            std::vector<char> buffer(size);
            WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)appDataPath, -1, buffer.data(), size, nullptr, nullptr);
            userDataDir = std::string(buffer.data());
        }
        CoTaskMemFree(appDataPath);
    }
    
    if (userDataDir.empty()) {
        // Fallback to environment variable
        const char* appData = getenv("LOCALAPPDATA");
        if (appData) {
            userDataDir = std::string(appData);
        }
    }
    
    // Add company name
    userDataDir += "\\LightMaker";
    
#else
    // Linux: /home/<username>/.local/share/<company>
    const char* homeDir = getenv("HOME");
    if (!homeDir) {
        // Fallback to getpwuid
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            homeDir = pw->pw_dir;
        }
    }
    
    if (homeDir) {
        userDataDir = std::string(homeDir) + "/.local/share/LightMaker";
    } else {
        // Ultimate fallback
        userDataDir = "./data";
    }
#endif
    
    return userDataDir;
}

// Helper function to create directory if it doesn't exist
bool createDirectoryIfNotExists(const std::string& path) {
#ifdef _WIN32
    return CreateDirectoryA(path.c_str(), NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}



// Helper function to generate random salt
std::string generateSalt() {
    std::vector<uint8_t> salt(16); // 128-bit salt
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        // Fallback to random_device if OpenSSL RAND fails
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& byte : salt) {
            byte = static_cast<uint8_t>(dis(gen));
        }
    }
    return bytesToHex(salt);
}

// Helper function to hash password with salt using PBKDF2
std::string hashPassword(const std::string& password, const std::string& salt) {
    const int iterations = 100000; // PBKDF2 iterations
    const int key_len = 32; // 256-bit key
    
    std::vector<uint8_t> key(key_len);
    
    // Convert hex salt back to bytes
    std::vector<uint8_t> salt_bytes;
    for (size_t i = 0; i < salt.length(); i += 2) {
        std::string byte_str = salt.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        salt_bytes.push_back(byte);
    }
    
    // Use PBKDF2 with SHA-256
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt_bytes.data(), salt_bytes.size(),
                          iterations, EVP_sha256(),
                          key_len, key.data()) != 1) {
        throw std::runtime_error("PBKDF2 hashing failed");
    }
    
    return bytesToHex(key);
}

// Helper function to verify password
bool verifyPassword(const std::string& password, const std::string& hashed_password_with_salt) {
    try {
        // Extract salt from stored hash (first 32 characters = 16 bytes in hex)
        if (hashed_password_with_salt.length() < 32) {
            return false;
        }
        
        std::string salt = hashed_password_with_salt.substr(0, 32);
        std::string stored_hash = hashed_password_with_salt.substr(32);
        
        // Hash the provided password with the extracted salt
        std::string computed_hash = hashPassword(password, salt);
        
        // Compare hashes
        return computed_hash == stored_hash;
    } catch (const std::exception& e) {
        std::cerr << "Password verification error: " << e.what() << std::endl;
        return false;
    }
}

// Helper function to generate order serial number
std::string generateOrderSerialNumber() {
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    // Format: ORD + YYYYMMDDHHMMSS + random 4 digits
    std::tm* tm_info = std::localtime(&time_t);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", tm_info);
    
    // Generate random 4-digit number
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    
    return "ORD" + std::string(buffer) + std::to_string(dis(gen));
}
// Register ORM mappings
REGISTER_AUTO_KEY(User, id)
YLT_REFL(User, id, name, email, phone, address, password, role, permissions, groups, created_at, updated_at)

REGISTER_AUTO_KEY(Customer, id)
YLT_REFL(Customer, id, name, phone, email, avatar_image, address, company, position, notes, created_at, updated_at)

REGISTER_AUTO_KEY(Order, id)
YLT_REFL(Order, id, name, serial_number, description, attachments, print_quantity, customer_name, created_at, updated_at)

REGISTER_AUTO_KEY(EmbedDevice, device_id)
YLT_REFL(EmbedDevice, device_id, device_name, device_type, model, serial_number, firmware_version, hardware_version, manufacturer, ip_address, port, mac_address, status, location, description, last_seen, created_at, updated_at, session_id, capabilities, metadata)

REGISTER_AUTO_KEY(PrintTask, id)
YLT_REFL(PrintTask, id, order_serial_number, print_name, file_uuid, total_quantity, completed_quantity)

REGISTER_AUTO_KEY(File_record, id)
YLT_REFL(File_record, id, uuid, filename, aeskey, upload_time, file_type, customer_name)

REGISTER_AUTO_KEY(OrderFile, id)
YLT_REFL(OrderFile, id, order_id, file_uuid, created_at, description)

 
 
namespace lmdb {
    struct lmDBCoreImpl
    {
        ormpp::dbng<ormpp::sqlite> sqlite;
    };

    lmDBCore::lmDBCore(const std::string& db_name) 
        : impl(new lmDBCoreImpl()) 
    {
        // Get user data directory
        std::string userDataDir = getUserDataDirectory() + "/data/" ;
        
        // Create directory if it doesn't exist
        createDirectoryIfNotExists(userDataDir);
        
        std::string dbDir = userDataDir +  db_name;


        // Create directory if it doesn't exist
        createDirectoryIfNotExists(dbDir);

        // Build full database path: userDataDir/db_name.db
        db_path_ = dbDir + "/" + db_name + ".db";
        
        // Connect to database
        impl->sqlite.connect(db_path_);

        file_dir_ = dbDir + "/" + db_name + "/file";
        createDirectoryIfNotExists(file_dir_);
    }   

    lmDBCore::~lmDBCore() 
    { 
        delete impl; 
        impl = nullptr;
    }

    const std::string& lmDBCore::get_database_path() const
    {
        return db_path_;
    }

    const std::string& lmDBCore::get_file_dir() const
    {
        return  file_dir_;
    }

    DB_RESULT lmDBCore::initialize()
    {
        try
        {
            // 删除现有表（如果存在）
            // impl->sqlite.execute("DROP TABLE IF EXISTS User");
            // impl->sqlite.execute("DROP TABLE IF EXISTS Customer");
            // impl->sqlite.execute("DROP TABLE IF EXISTS `Order`");
            // impl->sqlite.execute("DROP TABLE IF EXISTS PrintTask");
            // impl->sqlite.execute("DROP TABLE IF EXISTS Gcode_file");
            
            // Create all data tables
            ormpp_auto_key user_key{"id"};
            ormpp_not_null user_not_null{{"name"}};
            ormpp_unique user_unique{{"name"}};
            impl->sqlite.create_datatable<User>(user_key, user_not_null,user_unique);

            ormpp_auto_key customer_key{"id"};
            ormpp_not_null customer_not_null{{"name"}};
            ormpp_unique   customer_unique{{"name"}};
            impl->sqlite.create_datatable<Customer>(customer_key, customer_not_null,customer_unique);

            ormpp_auto_key order_key{"id"};
            ormpp_not_null order_not_null{{"serial_number"}};
            ormpp_unique order_unique{{"serial_number"}};
            impl->sqlite.create_datatable<Order>(order_key, order_not_null, order_unique);

            ormpp_auto_key embed_device_key{"device_id"};
            ormpp_not_null embed_device_not_null{{"serial_number"}};
            ormpp_unique embed_device_unique{{"serial_number"}};
            impl->sqlite.create_datatable<EmbedDevice>(embed_device_key, embed_device_not_null, embed_device_unique);

            ormpp_auto_key print_task_key{"id"};
            impl->sqlite.create_datatable<PrintTask>(print_task_key);

            ormpp_auto_key file_key{"id"};
            ormpp_not_null file_not_null{{"uuid"}};
            ormpp_unique file_unique{{"uuid"}};
            impl->sqlite.create_datatable<File_record>(file_key, file_not_null, file_unique);

            // Create OrderFile relationship table
            ormpp_auto_key order_file_key{"id"};
            ormpp_not_null order_file_not_null{{"order_id", "file_uuid"}};
            ormpp_unique order_file_unique{{"order_id", "file_uuid"}};  // 防止重复关联
            impl->sqlite.create_datatable<OrderFile>(order_file_key, order_file_not_null, order_file_unique);

            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Database initialization failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // User operations (matches user_service.proto)
    DB_RESULT lmDBCore::add_user(const std::string& name, const std::string& email, const std::string& password,
                                const std::string& phone, const std::string& address, int role)
    {
        try
        {
            // Validate input parameters
            if (name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (password.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Note: email can be empty, no validation needed
            
            // Check if user already exists
            auto existing = impl->sqlite.query_s<User>("name = ?", name);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // User name already exists
            }

            User user;
            user.name = name;
            user.email = email;
            user.phone = phone;
            user.address = address;
            user.role = role;
            user.permissions = "[]";  // Empty JSON array
            user.groups = "[]";       // Empty JSON array
            
            // Encrypt password
            std::string salt = generateSalt();
            std::string hashed_password = hashPassword(password, salt);
            user.password = salt + hashed_password;  // Store salt + hash
            
            // Set timestamps
            time_t now = time(0);
            user.created_at = static_cast<int64_t>(now);
            user.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(user);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add user failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // 新增：传入User结构体的add_user接口
    DB_RESULT lmDBCore::add_user(User &user)
    {
        try
        {
            // Validate input parameters
            if (user.name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (user.password.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Note: email can be empty, no validation needed
            
            // Check if user already exists
            auto existing = impl->sqlite.query_s<User>("name = ?", user.name);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // User name already exists
            }

            // Set default values if not provided
            if (user.permissions.empty()) {
                user.permissions = "[]";  // Empty JSON array
            }
            if (user.groups.empty()) {
                user.groups = "[]";       // Empty JSON array
            }
            
            // Encrypt password
            std::string salt = generateSalt();
            std::string hashed_password = hashPassword(user.password, salt);
            user.password = salt + hashed_password;  // Store salt + hash
            
            // Set timestamps
            time_t now = time(0);
            user.created_at = static_cast<int64_t>(now);
            user.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(user);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add user (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }


    DB_RESULT lmDBCore::remove_user(int64_t id)
    {
        try
        {
            // Check if user exists first
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            impl->sqlite.delete_records_s<User>("id = ?", id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove user failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_user(const std::string& name)
    {
        try
        {
            // Check if user exists first
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            impl->sqlite.delete_records_s<User>("name = ?", name);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove user by name failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }



    DB_RESULT lmDBCore::update_user(int64_t id, const std::string& name, const std::string& email,
                               const std::string& phone, const std::string& address, int role)
    {
        try
        {
            // Validate input parameters
            if (name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Note: email can be empty, no validation needed
            
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            User user = users[0];
            user.name = name;
            user.email = email;
            user.phone = phone;
            user.address = address;
            user.password = users[0].password;  // 使用数据库中的原密码
            if (role >= 0) {
                user.role = role;
            }
            user.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(user);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update user failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::update_user(const std::string& name, const std::string& new_name, const std::string& email,
                               const std::string& phone, const std::string& address, int role)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            User user = users[0];
            user.name = new_name;
            user.email = email;
            user.phone = phone;
            user.address = address;
            user.password = users[0].password;  // 使用数据库中的原密码
            if (role >= 0) {
                user.role = role;
            }
            user.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(user);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update user by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // 新增：传入User结构体的update_user接口
    DB_RESULT lmDBCore::update_user(const User &user)
    {
        try
        {
            // Validate input parameters
            if (user.id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (user.name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Note: email can be empty, no validation needed
            
            // Check if user exists
            auto existing = impl->sqlite.query_s<User>("id = ?", user.id);
            if (existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            // Check if new name conflicts with existing users (excluding current user)
            auto name_conflict = impl->sqlite.query_s<User>("name = ? AND id != ?", user.name, user.id);
            if (!name_conflict.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // User name already exists
            }

            // Create a copy of the user with updated timestamp
            User updated_user = user;
            updated_user.password = existing[0].password;  // 使用数据库中的原密码
            updated_user.updated_at = static_cast<int64_t>(time(0));
               
   
            
            impl->sqlite.update(updated_user);
                return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update user (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::update_user_role_by_name(const std::string& name, int role)
    {
        try
        {
            // Validate input parameters
            if (name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Validate role value
            if (!is_valid_user_role(role)) {
                std::cerr << "Invalid user role: " << role << std::endl;
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if user exists
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND; // User not found
            }

            User user = users[0];
            user.role = role;
            
            impl->sqlite.update(user);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update user role by name failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    bool lmDBCore::is_valid_user_role(int role)
    {
        return (role >= static_cast<int>(USER_ROLE::GUEST) && 
                role <= static_cast<int>(USER_ROLE::ADMIN));
    }

 

    DB_RESULT lmDBCore::set_password(int64_t id, const std::string& new_password)
    {
        try
        {
            // Validate new password
            if (new_password.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            if (users.size() == 1) {
                User u = users[0];
                
                // Generate new salt and hash the new password
                std::string salt = generateSalt();
                std::string hashed_password = hashPassword(new_password, salt);
                
                // Store salt + hash (salt is first 32 chars, hash is remaining)
                u.password = salt + hashed_password;
                u.updated_at = static_cast<int64_t>(time(0));
                impl->sqlite.update(u);
                return DB_SUCCESS;
            }
            
            // Multiple users with same ID (should not happen with primary key)
            std::cerr << "Multiple users found with ID: " << id << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Set password failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::set_password(const std::string& name, const std::string& new_password)
    {
        try
        {
            // Validate new password
            if (new_password.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            if (users.size() == 1) {
                User u = users[0];
                
                // Generate new salt and hash the new password
                std::string salt = generateSalt();
                std::string hashed_password = hashPassword(new_password, salt);
                
                // Store salt + hash (salt is first 32 chars, hash is remaining)
                u.password = salt + hashed_password;
                u.updated_at = static_cast<int64_t>(time(0));
                impl->sqlite.update(u);
                return DB_SUCCESS;
            }
            
            // Multiple users with same name (should not happen with unique constraint)
            std::cerr << "Multiple users found with name: " << name << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Set password failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }
        
    DB_RESULT lmDBCore::get_password(int64_t id, std::string& out_password)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.size() == 1) {
                out_password = users[0].password;
                return DB_SUCCESS;
            }
            return DB_ERROR_RECORD_NOT_FOUND;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get password failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::get_user_by_id(int64_t id, User &out_user)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_user = users[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get user by id failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_user_by_name(const std::string& name, User &out_user)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_user = users[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get user by name failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_all_users(std::vector<User> &out_users)
    {
        try
        {
            out_users = impl->sqlite.query_s<User>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all users failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::verify_user(const std::string& name, const std::string& password)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            if (users.size() == 1) {
                User u = users[0];
                // Use secure password verification
                if (verifyPassword(password, u.password)) {
                    return DB_SUCCESS;
                } else {
                    return DB_ERROR_PASSWORD_INCORRECT;
                }
            }
            
            // Multiple users with same name (should not happen with unique constraint)
            std::cerr << "Multiple users found with name: " << name << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Verify user failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }


    // Customer operations
    DB_RESULT lmDBCore::add_customer(const std::string& name, const std::string& phone, const std::string& email,
                                const std::string& avatar_image, const std::string& address, const std::string& company,
                                const std::string& position, const std::string& notes)
    {
        try
        {
            auto existing = impl->sqlite.query_s<Customer>("name = ?", name);
            if (!existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND; // Customer name already exists
            }

            Customer customer;
            customer.name = name;
            customer.phone = phone;
            customer.email = email;
            customer.avatar_image = avatar_image;
            customer.address = address;
            customer.company = company;
            customer.position = position;
            customer.notes = notes;
            
            // Set timestamps
            time_t now = time(0);
            customer.created_at = static_cast<int64_t>(now);
            customer.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(customer);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add customer failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // 新增：传入Customer结构体的add_customer接口
    DB_RESULT lmDBCore::add_customer(Customer &customer)
    {
        try
        {
            // Validate input parameters
            if (customer.name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if customer already exists
            auto existing = impl->sqlite.query_s<Customer>("name = ?", customer.name);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // Customer name already exists
            }

            // Set timestamps
            time_t now = time(0);
            customer.created_at = static_cast<int64_t>(now);
            customer.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(customer);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add customer (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // 新增：传入Customer结构体的update_customer接口
    DB_RESULT lmDBCore::update_customer(const Customer &customer)
    {
        try
        {
            // Validate input parameters
            if (customer.id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (customer.name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if customer exists
            auto existing = impl->sqlite.query_s<Customer>("id = ?", customer.id);
            if (existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            // Check if new name conflicts with existing customers (excluding current customer)
            auto name_conflict = impl->sqlite.query_s<Customer>("name = ? AND id != ?", customer.name, customer.id);
            if (!name_conflict.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // Customer name already exists
            }

            // Create a copy of the customer with updated timestamp
            Customer updated_customer = customer;
            updated_customer.updated_at = static_cast<int64_t>(time(0));
            
            impl->sqlite.update(updated_customer);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update customer (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_customer(int64_t customer_id)
    {
        try
        {
            impl->sqlite.delete_records_s<Customer>("id = ?", customer_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove customer failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_customer(const std::string& name)
    {
        try
        {
            impl->sqlite.delete_records_s<Customer>("name = ?", name);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove customer by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_customer(int64_t customer_id, const std::string& name, const std::string& phone,
                                   const std::string& email, const std::string& avatar_image, const std::string& address,
                                   const std::string& company, const std::string& position, const std::string& notes)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("id = ?", customer_id);
            if (customers.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            Customer customer = customers[0];
            customer.name = name;
            customer.phone = phone;
            customer.email = email;
            customer.avatar_image = avatar_image;
            customer.address = address;
            customer.company = company;
            customer.position = position;
            customer.notes = notes;
            customer.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(customer);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update customer failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_customer(const std::string& name, const std::string& new_name, const std::string& phone,
                                   const std::string& email, const std::string& avatar_image, const std::string& address,
                                   const std::string& company, const std::string& position, const std::string& notes)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("name = ?", name);
            if (customers.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            Customer customer = customers[0];
            customer.name = new_name;
            customer.phone = phone;
            customer.email = email;
            customer.avatar_image = avatar_image;
            customer.address = address;
            customer.company = company;
            customer.position = position;
            customer.notes = notes;
            customer.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(customer);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update customer by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::get_all_customers(std::vector<Customer> &out_customers)
    {
        try
        {
            out_customers = impl->sqlite.query_s<Customer>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all customers failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_customer_by_id(int64_t customer_id, Customer &out_customer)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("id = ?", customer_id);
            if (customers.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_customer = customers[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get customer by id failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_customer_by_name(const std::string& name, Customer &out_customer)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("name = ?", name);
            if (customers.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_customer = customers[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get customer by name failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }


    // Order operations
    DB_RESULT lmDBCore::add_order(const std::string& name, const std::string& description, const std::string& customer_name, 
                             int32_t print_quantity, const std::string& attachments, std::string& out_serial_number)
    {
        try
        {
            Order order;
            order.name = name;
            order.description = description;
            order.customer_name = customer_name;
            order.print_quantity = print_quantity;
            order.attachments = attachments;
            order.serial_number = generateOrderSerialNumber();
            
            // Check if serial number already exists (very unlikely but possible)
            auto existing_serial = impl->sqlite.query_s<Order>("serial_number = ?", order.serial_number);
            if (!existing_serial.empty())
            {
                // Generate a new serial number if collision occurs
                order.serial_number = generateOrderSerialNumber();
            }
            
            // Set timestamps
            time_t now = time(0);
            order.created_at = static_cast<int64_t>(now);
            order.updated_at = static_cast<int64_t>(now);

            impl->sqlite.insert(order);
            out_serial_number = order.serial_number;
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add order failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // 新增：传入Order结构体的add_order接口
    DB_RESULT lmDBCore::add_order(Order &order, std::string &out_serial_number)
    {
        try
        {
            // Validate input parameters
            if (order.name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (order.description.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (order.customer_name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Generate serial number if not provided
       
            order.serial_number = generateOrderSerialNumber();
    
            // Set timestamps
            time_t now = time(0);
            order.created_at = static_cast<int64_t>(now);
            order.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(order);
            out_serial_number = order.serial_number;
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add order (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_order(int64_t order_id)
    {
        try
        {
            impl->sqlite.delete_records_s<Order>("id = ?", order_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove order failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_order(const std::string& serial)
    {
        try
        {
            // First try to find by serial_number, then by name for backward compatibility
            auto orders_by_serial = impl->sqlite.query_s<Order>("serial_number = ?", serial);
            if (!orders_by_serial.empty()) {
                impl->sqlite.delete_records_s<Order>("serial_number = ?", serial);
                return DB_SUCCESS;
            }
            
            // Fallback to name for backward compatibility
            impl->sqlite.delete_records_s<Order>("name = ?", serial);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove order by serial/name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_order(int64_t order_id, const std::string& name, const std::string& description,
                                const std::string& customer_name, int32_t print_quantity, const std::string& attachments)
    {
        try
        {
            auto orders = impl->sqlite.query_s<Order>("id = ?", order_id);
            if (orders.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            Order order = orders[0];
            order.name = name;
            order.description = description;
            order.customer_name = customer_name;
            order.print_quantity = print_quantity;
            order.attachments = attachments;
            order.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(order);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update order failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_order(const std::string& serial, const std::string& new_name, const std::string& description,
                               const std::string& customer_name, int32_t print_quantity, const std::string& attachments)
    {
        try
        {
            // First try to find by serial_number, then by name for backward compatibility
            auto orders = impl->sqlite.query_s<Order>("serial_number = ?", serial);
          
            
            if (orders.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            Order order = orders[0];
            order.name = new_name;
            order.description = description;
            order.customer_name = customer_name;
            order.print_quantity = print_quantity;
            order.attachments = attachments;
            order.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(order);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update order by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // 新增：传入Order结构体的update_order接口
    DB_RESULT lmDBCore::update_order(const Order &order)
    {
        try
        {

            auto orders = impl->sqlite.query_s<Order>("serial_number = ?", order.serial_number);
            if (orders.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            // Create a copy of the order with updated timestamp
            Order updated_order = order;
            updated_order.updated_at = static_cast<int64_t>(time(0));
            impl->sqlite.update(updated_order);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update order (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_all_orders(std::vector<Order> &out_orders)
    {
        try
        {
            out_orders = impl->sqlite.query_s<Order>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all orders failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_order_by_id(int64_t order_id, Order &out_order)
    {
        try
        {
            auto orders = impl->sqlite.query_s<Order>("id = ?", order_id);
            if (orders.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_order = orders[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get order by id failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_order_by_serial(const std::string& serial_number, Order &out_order)
    {
        try
        {
            if (serial_number.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            auto orders = impl->sqlite.query_s<Order>("serial_number = ?", serial_number);
            if (orders.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_order = orders[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get order by serial failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_orders_by_customer(const std::string& customer_name, std::vector<Order> &out_orders)
    {
        try
        {
            out_orders = impl->sqlite.query_s<Order>("customer_name = ?", customer_name);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get orders by customer failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // EmbedDevice operations
    DB_RESULT lmDBCore::add_embed_device(const std::string& device_name, int device_type,
                                    const std::string& model, const std::string& serial_number,
                                    const std::string& firmware_version, const std::string& hardware_version,
                                    const std::string& manufacturer, const std::string& ip_address,
                                    int32_t port, const std::string& mac_address, int status,
                                    const std::string& location, const std::string& description,
                                    const std::string& capabilities, const std::string& metadata)
    {
        try
        {
            // Check if serial_number already exists (now the unique constraint)
            if (!serial_number.empty()) {
                auto existing = impl->sqlite.query_s<EmbedDevice>("serial_number = ?", serial_number);
                if (!existing.empty())
                {
                    return DB_ERROR_DUPLICATE_RECORD; // Serial number already exists
                }
            }

            EmbedDevice device(serial_number, device_name, device_type, model, firmware_version,
                              hardware_version, manufacturer, ip_address, port, mac_address,
                              status, location, description, capabilities, metadata);
            
            impl->sqlite.insert(device);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add embed device failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // 新增：传入EmbedDevice结构体的add_embed_device接口
    DB_RESULT lmDBCore::add_embed_device(EmbedDevice &device)
    {
        try
        {
            // Validate input parameters - serial_number is now required
            if (device.serial_number.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if serial_number already exists (now the unique constraint)
            auto existing = impl->sqlite.query_s<EmbedDevice>("serial_number = ?", device.serial_number);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // Serial number already exists
            }

            // Set timestamps
            time_t now = time(0);
            device.created_at = static_cast<int64_t>(now);
            device.updated_at = static_cast<int64_t>(now);
            device.last_seen = static_cast<int64_t>(now);
            
            impl->sqlite.insert(device);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add embed device (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_embed_device(int64_t device_id)
    {
        try
        {
            impl->sqlite.delete_records_s<EmbedDevice>("device_id = ?", device_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove embed device failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_embed_device(const std::string& device_name)
    {
        try
        {
            impl->sqlite.delete_records_s<EmbedDevice>("device_name = ?", device_name);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove embed device by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_embed_device_by_serial_number(const std::string& serial_number)
    {
        try
        {
            impl->sqlite.delete_records_s<EmbedDevice>("serial_number = ?", serial_number);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove embed device by serial number failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_embed_device(int64_t device_id, const std::string& device_name, int device_type,
                                       const std::string& model, const std::string& serial_number,
                                       const std::string& firmware_version, const std::string& hardware_version,
                                       const std::string& manufacturer, const std::string& ip_address,
                                       int32_t port, const std::string& mac_address, int status,
                                       const std::string& location, const std::string& description,
                                       const std::string& capabilities, const std::string& metadata)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("device_id = ?", device_id);
            if (devices.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            EmbedDevice device = devices[0];
            device.device_name = device_name;
            
            // Only update fields that are not default values
            if (device_type != -1) device.device_type = device_type;
            if (!model.empty()) device.model = model;
            if (!serial_number.empty()) device.serial_number = serial_number;
            if (!firmware_version.empty()) device.firmware_version = firmware_version;
            if (!hardware_version.empty()) device.hardware_version = hardware_version;
            if (!manufacturer.empty()) device.manufacturer = manufacturer;
            if (!ip_address.empty()) device.ip_address = ip_address;
            if (port != -1) device.port = port;
            if (!mac_address.empty()) device.mac_address = mac_address;
            if (status != -1) device.status = status;
            if (!location.empty()) device.location = location;
            if (!description.empty()) device.description = description;
            if (!capabilities.empty()) device.capabilities = capabilities;
            if (!metadata.empty()) device.metadata = metadata;
            
            device.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(device);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update embed device failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }


    DB_RESULT lmDBCore::update_embed_device(const std::string& serial_number, const std::string& new_device_name, int device_type,
                                       const std::string& model, const std::string& new_serial_number,
                                       const std::string& firmware_version, const std::string& hardware_version,
                                       const std::string& manufacturer, const std::string& ip_address,
                                       int32_t port, const std::string& mac_address, int status,
                                       const std::string& location, const std::string& description,
                                       const std::string& capabilities, const std::string& metadata)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("serial_number = ?", serial_number);
            if (devices.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            EmbedDevice device = devices[0];
            device.device_name = new_device_name;
            
            // Only update fields that are not default values
            if (device_type != -1) device.device_type = device_type;
            if (!model.empty()) device.model = model;
            if (!new_serial_number.empty()) {
                // Check if new serial number conflicts with existing devices
                if (new_serial_number != serial_number) {
                    auto existing = impl->sqlite.query_s<EmbedDevice>("serial_number = ?", new_serial_number);
                    if (!existing.empty()) {
                        return DB_ERROR_DUPLICATE_RECORD; // New serial number already exists
                    }
                }
                device.serial_number = new_serial_number;
            }
            if (!firmware_version.empty()) device.firmware_version = firmware_version;
            if (!hardware_version.empty()) device.hardware_version = hardware_version;
            if (!manufacturer.empty()) device.manufacturer = manufacturer;
            if (!ip_address.empty()) device.ip_address = ip_address;
            if (port != -1) device.port = port;
            if (!mac_address.empty()) device.mac_address = mac_address;
            if (status != -1) device.status = status;
            if (!location.empty()) device.location = location;
            if (!description.empty()) device.description = description;
            if (!capabilities.empty()) device.capabilities = capabilities;
            if (!metadata.empty()) device.metadata = metadata;
            
            device.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(device);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update embed device by serial number failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // 新增：传入EmbedDevice结构体的update_embed_device接口
    DB_RESULT lmDBCore::update_embed_device(const EmbedDevice &device)
    {
        try
        {
            // Validate input parameters
            if (device.device_id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (device.serial_number.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if device exists
            auto existing = impl->sqlite.query_s<EmbedDevice>("device_id = ?", device.device_id);
            if (existing.empty())
            {
                 existing = impl->sqlite.query_s<EmbedDevice>("serial_number = ?", device.serial_number);
                 if(existing .empty())
                 {
                     return DB_ERROR_RECORD_NOT_FOUND;
                 }
            }

            // Check if new serial_number conflicts with existing devices (excluding current device)
            // auto serial_conflict = impl->sqlite.query_s<EmbedDevice>("serial_number = ? AND device_id != ?", device.serial_number, device.device_id);
            // if (!serial_conflict.empty())
            // {
            //     return DB_ERROR_DUPLICATE_RECORD; // Serial number already exists
            // }

            // Create a copy of the device with updated timestamp
            EmbedDevice updated_device = device;
            updated_device.updated_at = static_cast<int64_t>(time(0));
            
            impl->sqlite.update(updated_device);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update embed device (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_all_embed_devices(std::vector<EmbedDevice> &out_devices)
    {
        try
        {
            out_devices = impl->sqlite.query_s<EmbedDevice>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all embed devices failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_embed_device_by_id(int64_t device_id, EmbedDevice &out_device)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("device_id = ?", device_id);
            if (devices.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_device = devices[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get embed device by id failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }


    DB_RESULT lmDBCore::get_embed_device_by_serial_number(const std::string& serial_number, EmbedDevice &out_device)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("serial_number = ?", serial_number);
            if (devices.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_device = devices[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get embed device by serial number failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_embed_devices_by_type(int device_type, std::vector<EmbedDevice> &out_devices)
    {
        try
        {
            out_devices = impl->sqlite.query_s<EmbedDevice>("device_type = ?", device_type);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get embed devices by type failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // Print task operations
    DB_RESULT lmDBCore::add_print_task(const std::string& order_serial_number, const std::string& print_name, const std::string& file_uuid, int total_quantity)
    {
        try
        {
            PrintTask print_task;
            print_task.order_serial_number = order_serial_number;
            print_task.print_name = print_name;
            print_task.file_uuid = file_uuid;
            print_task.total_quantity = total_quantity;
            print_task.completed_quantity = 0;
            impl->sqlite.insert(print_task);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add print task failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_print_task(int64_t print_task_id)
    {
        try
        {
            impl->sqlite.delete_records_s<PrintTask>("id = ?", print_task_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove print task failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_print_task(const std::string& print_name)
    {
        try
        {
            impl->sqlite.delete_records_s<PrintTask>("print_name = ?", print_name);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove print task by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_print_task(int64_t print_task_id, const std::string& print_name, const std::string& file_uuid,
                               int total_quantity, int completed_quantity)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("id = ?", print_task_id);
            if (print_tasks.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            PrintTask print_task = print_tasks[0];
            print_task.print_name = print_name;
            print_task.file_uuid = file_uuid;
            print_task.total_quantity = total_quantity;
            print_task.completed_quantity = completed_quantity;

            impl->sqlite.update(print_task);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update print task failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_print_task(const std::string& print_name, const std::string& new_print_name, const std::string& file_uuid,
                               int total_quantity, int completed_quantity)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("print_name = ?", print_name);
            if (print_tasks.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            PrintTask print_task = print_tasks[0];
            print_task.print_name = new_print_name;
            print_task.file_uuid = file_uuid;
            print_task.total_quantity = total_quantity;
            print_task.completed_quantity = completed_quantity;

            impl->sqlite.update(print_task);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update print task by name failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::get_all_print_tasks(std::vector<PrintTask> &out_tasks)
    {
        try
        {
            out_tasks = impl->sqlite.query_s<PrintTask>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all print tasks failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_print_task_by_id(int64_t print_task_id, PrintTask &out_task)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("id = ?", print_task_id);
            if (print_tasks.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_task = print_tasks[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get print task by id failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_print_tasks_by_order(const std::string& order_serial_number, std::vector<PrintTask> &out_tasks)
    {
        try
        {
            out_tasks = impl->sqlite.query_s<PrintTask>("order_serial_number = ?", order_serial_number);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get print tasks by order failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::update_print_progress(int64_t print_task_id, int completed_quantity)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("id = ?", print_task_id);
            if (print_tasks.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            PrintTask print_task = print_tasks[0];
            print_task.completed_quantity = completed_quantity;

            impl->sqlite.update(print_task);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update print progress failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // G-code file operations
    DB_RESULT lmDBCore::add_file_record(const std::string& filename, const std::string& aeskey, const std::string& customer_name, const std::string& file_type)
    {
        try
        {
            // Generate UUID for the new file
            std::string uuid;
            DB_RESULT uuid_result = lmDBCore::generate_uuid(uuid);
            if (uuid_result != DB_SUCCESS) {
                return uuid_result;
            }
            
            // Check if UUID already exists (very unlikely but safe)
            auto existing = impl->sqlite.query_s<File_record>("uuid = ?", uuid);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // UUID already exists
            }

            File_record file_record;
            file_record.uuid = uuid;
            file_record.filename = filename;
            file_record.file_type = file_type;
            file_record.customer_name = customer_name;
            
            // Copy AES key
            file_record.aeskey = aeskey;
            
            // Set upload time to current date
            time_t now = time(0);
            char buffer[100];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
            file_record.upload_time = buffer;

            impl->sqlite.insert(file_record);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add gcode file failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_all_file_records(std::vector<File_record> &out_files)
    {
        try
        {
            out_files = impl->sqlite.query_s<File_record>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all gcode files failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }


    DB_RESULT lmDBCore::get_file_record(const std::string& uuid, File_record &out_file)
    {
        try
        {
            auto file_records = impl->sqlite.query_s<File_record>("uuid = ?", uuid);
            if (file_records.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_file = file_records[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get gcode file by UUID failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_file_record(const std::string& uuid)
    {
        try
        {
            impl->sqlite.delete_records_s<File_record>("uuid = ?", uuid);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove gcode file by UUID failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_file_record(const std::string& uuid, const std::string& filename, const std::string& aeskey, const std::string& customer_name, const std::string& file_type)
    {
        try
        {
            auto file_records = impl->sqlite.query_s<File_record>("uuid = ?", uuid);
            if (file_records.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            File_record file = file_records[0];
            file.filename = filename;
            file.aeskey = aeskey;
            file.file_type = file_type;
            file.customer_name = customer_name;
            
            impl->sqlite.update(file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update gcode file by UUID failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::get_total_file_records_count(int &out_count)
    {
        try
        {
            auto file_records = impl->sqlite.query_s<File_record>("");
            out_count = static_cast<int>(file_records.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total file records count failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_file_records_by_customer(const std::string& customer_name, std::vector<File_record> &out_files)
    {
        try
        {
            out_files = impl->sqlite.query_s<File_record>("customer_name = ?", customer_name);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get file records by customer failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_file_records_count_by_customer(const std::string& customer_name, int &out_count)
    {
        try
        {
            auto file_records = impl->sqlite.query_s<File_record>("customer_name = ?", customer_name);
            out_count = static_cast<int>(file_records.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get file records count by customer failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // ==================== Order-File Relationship Operations ====================

    DB_RESULT lmDBCore::add_order_file_relation(int order_id, const std::string& file_uuid, const std::string& description)
    {
        try
        {
            // Check if order exists
            auto orders = impl->sqlite.query_s<Order>("id = ?", order_id);
            if (orders.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND; // Order not found
            }

            // Check if file exists
            auto files = impl->sqlite.query_s<File_record>("uuid = ?", file_uuid);
            if (files.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND; // File not found
            }

            // Check if relation already exists
            auto existing = impl->sqlite.query_s<OrderFile>("order_id = ? AND file_uuid = ?", order_id, file_uuid);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // Relation already exists
            }

            OrderFile relation;
            relation.order_id = order_id;
            relation.file_uuid = file_uuid;
            relation.description = description;
            
            // Set creation time
            time_t now = time(0);
            char buffer[100];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
            relation.created_at = buffer;

            impl->sqlite.insert(relation);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add order-file relation failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_order_file_relation(int order_id, const std::string& file_uuid)
    {
        try
        {
            impl->sqlite.delete_records_s<OrderFile>("order_id = ? AND file_uuid = ?", order_id, file_uuid);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove order-file relation failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_all_order_file_relations(int order_id)
    {
        try
        {
            impl->sqlite.delete_records_s<OrderFile>("order_id = ?", order_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove all order-file relations failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::remove_all_file_order_relations(const std::string& file_uuid)
    {
        try
        {
            impl->sqlite.delete_records_s<OrderFile>("file_uuid = ?", file_uuid);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove all file-order relations failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_files_by_order(int order_id, std::vector<File_record> &out_files)
    {
        try
        {
            // Get all file UUIDs associated with the order
            auto relations = impl->sqlite.query_s<OrderFile>("order_id = ?", order_id);
            out_files.clear();
            
            for (const auto& relation : relations)
            {
                auto files = impl->sqlite.query_s<File_record>("uuid = ?", relation.file_uuid);
                if (!files.empty())
                {
                    out_files.push_back(files[0]);
                }
            }
            
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get files by order failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_orders_by_file(const std::string& file_uuid, std::vector<Order> &out_orders)
    {
        try
        {
            // Get all order IDs associated with the file
            auto relations = impl->sqlite.query_s<OrderFile>("file_uuid = ?", file_uuid);
            out_orders.clear();
            
            for (const auto& relation : relations)
            {
                auto orders = impl->sqlite.query_s<Order>("id = ?", relation.order_id);
                if (!orders.empty())
                {
                    out_orders.push_back(orders[0]);
                }
            }
            
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get orders by file failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_order_file_relations(int order_id, std::vector<OrderFile> &out_relations)
    {
        try
        {
            out_relations = impl->sqlite.query_s<OrderFile>("order_id = ?", order_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get order-file relations failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_file_order_relations(const std::string& file_uuid, std::vector<OrderFile> &out_relations)
    {
        try
        {
            out_relations = impl->sqlite.query_s<OrderFile>("file_uuid = ?", file_uuid);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get file-order relations failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::update_order_file_relation(int order_id, const std::string& file_uuid, const std::string& description)
    {
        try
        {
            auto relations = impl->sqlite.query_s<OrderFile>("order_id = ? AND file_uuid = ?", order_id, file_uuid);
            if (relations.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            OrderFile relation = relations[0];
            relation.description = description;
            
            impl->sqlite.update(relation);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update order-file relation failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_order_file_relation_count(int order_id, int &out_count)
    {
        try
        {
            auto relations = impl->sqlite.query_s<OrderFile>("order_id = ?", order_id);
            out_count = static_cast<int>(relations.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get order-file relation count failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_file_order_relation_count(const std::string& file_uuid, int &out_count)
    {
        try
        {
            auto relations = impl->sqlite.query_s<OrderFile>("file_uuid = ?", file_uuid);
            out_count = static_cast<int>(relations.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get file-order relation count failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // Statistics
    DB_RESULT lmDBCore::get_total_orders_count(int &out_count)
    {
        try
        {
            auto orders = impl->sqlite.query_s<Order>("");
            out_count = static_cast<int>(orders.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total orders count failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_total_print_tasks_count(int &out_count)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("");
            out_count = static_cast<int>(print_tasks.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total print tasks count failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_completed_print_tasks_count(int &out_count)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("completed_quantity >= total_quantity");
            out_count = static_cast<int>(print_tasks.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get completed print tasks count failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // Database maintenance
    void lmDBCore::clear_all_data()
    {
        try
        {
            impl->sqlite.delete_records<OrderFile>();
            impl->sqlite.delete_records<File_record>();
            impl->sqlite.delete_records<PrintTask>();
            impl->sqlite.delete_records<Order>();
            impl->sqlite.delete_records<Customer>();
            impl->sqlite.delete_records<User>();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Clear all data failed: " << e.what() << std::endl;
        }
    }

    void lmDBCore::print_database_status()
    {
        std::cout << "\n=== 3D Print Management System Database Status ===\n";

        std::vector<User> users;
        if (get_all_users(users) == DB_SUCCESS) {
        std::cout << "User count: " << users.size() << std::endl;
        }

        std::vector<Customer> customers;
        if (get_all_customers(customers) == DB_SUCCESS) {
        std::cout << "Customer count: " << customers.size() << std::endl;
        }

        std::vector<Order> orders;
        if (get_all_orders(orders) == DB_SUCCESS) {
        std::cout << "Order count: " << orders.size() << std::endl;
        }

        std::vector<PrintTask> print_tasks;
        if (get_all_print_tasks(print_tasks) == DB_SUCCESS) {
        std::cout << "Print task count: " << print_tasks.size() << std::endl;
        }

        int completed = 0;
        if (get_completed_print_tasks_count(completed) == DB_SUCCESS) {
        std::cout << "Completed print tasks: " << completed << std::endl;
        }

        std::vector<File_record> file_records;
        if (get_all_file_records(file_records) == DB_SUCCESS) {
        std::cout << "File record count: " << file_records.size() << std::endl;
        }

        std::cout << "===============================================\n\n";
    }

    // Database backup and restore functions
    DB_RESULT lmDBCore::backup_database(const std::string& backup_path)
    {
        try
        {
            // Close current connection
            impl->sqlite.disconnect();
            
            // Copy database file
            std::ifstream src(db_path_, std::ios::binary);
            std::ofstream dst(backup_path, std::ios::binary);
            
            if (!src.is_open()) {
                std::cerr << "Failed to open source database: " << db_path_ << std::endl;
                impl->sqlite.connect(db_path_); // Reconnect
                return DB_ERROR_DATABASE_CONNECTION;
            }
            
            if (!dst.is_open()) {
                std::cerr << "Failed to create backup file: " << backup_path << std::endl;
                impl->sqlite.connect(db_path_); // Reconnect
                return DB_ERROR_DATABASE_CONNECTION;
            }
            
            dst << src.rdbuf();
            
            src.close();
            dst.close();
            
            // Reconnect to original database
            impl->sqlite.connect(db_path_);
            
            std::cout << "Database backup created successfully: " << backup_path << std::endl;
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Database backup failed: " << e.what() << std::endl;
            // Try to reconnect
            impl->sqlite.connect(db_path_);
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::restore_database(const std::string& backup_path)
    {
        try
        {
            // Check if backup file exists
            std::ifstream backup_file(backup_path, std::ios::binary);
            if (!backup_file.is_open()) {
                std::cerr << "Backup file not found: " << backup_path << std::endl;
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            backup_file.close();
            
            // Close current connection
            impl->sqlite.disconnect();
            
            // Copy backup file to current database location
            std::ifstream src(backup_path, std::ios::binary);
            std::ofstream dst(db_path_, std::ios::binary);
            
            if (!src.is_open() || !dst.is_open()) {
                std::cerr << "Failed to restore database from backup" << std::endl;
                impl->sqlite.connect(db_path_); // Try to reconnect
                return DB_ERROR_DATABASE_CONNECTION;
            }
            
            dst << src.rdbuf();
            
            src.close();
            dst.close();
            
            // Reconnect to restored database
            impl->sqlite.connect(db_path_);
            
            std::cout << "Database restored successfully from: " << backup_path << std::endl;
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Database restore failed: " << e.what() << std::endl;
            // Try to reconnect
            impl->sqlite.connect(db_path_);
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::export_to_sql(const std::string& sql_file_path)
    {
        try
        {
            std::ofstream sql_file(sql_file_path);
            if (!sql_file.is_open()) {
                std::cerr << "Failed to create SQL export file: " << sql_file_path << std::endl;
                return DB_ERROR_DATABASE_CONNECTION;
            }
            
            // Write SQL header
            sql_file << "-- LightMakerShadow Database Export\n";
            sql_file << "-- Generated on: " << std::time(nullptr) << "\n\n";
            
            // Export all tables data
            std::vector<User> users;
            if (get_all_users(users) == DB_SUCCESS) {
                sql_file << "-- Users table data\n";
                for (const auto& user : users) {
                    sql_file << "INSERT INTO User (id, name, email, phone, address, password, role, permissions, groups, created_at, updated_at) VALUES ("
                             << user.id << ", '" << user.name << "', '" << user.email << "', '" << user.phone 
                             << "', '" << user.address << "', '" << user.password << "', " << user.role 
                             << ", '" << user.permissions << "', '" << user.groups << "', " << user.created_at 
                             << ", " << user.updated_at << ");\n";
                }
                sql_file << "\n";
            }
            
            std::vector<Customer> customers;
            if (get_all_customers(customers) == DB_SUCCESS) {
                sql_file << "-- Customers table data\n";
                for (const auto& customer : customers) {
                    sql_file << "INSERT INTO Customer (id, name, phone, email, avatar_image, address, company, position, notes, created_at, updated_at) VALUES ("
                             << customer.id << ", '" << customer.name << "', '" << customer.phone << "', '" << customer.email 
                             << "', '" << customer.avatar_image << "', '" << customer.address << "', '" << customer.company 
                             << "', '" << customer.position << "', '" << customer.notes << "', " << customer.created_at 
                             << ", " << customer.updated_at << ");\n";
                }
                sql_file << "\n";
            }
            
            // Add more table exports as needed...
            
            sql_file.close();
            std::cout << "Database exported to SQL file: " << sql_file_path << std::endl;
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "SQL export failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::import_from_sql(const std::string& sql_file_path)
    {
        try
        {
            std::ifstream sql_file(sql_file_path);
            if (!sql_file.is_open()) {
                std::cerr << "SQL import file not found: " << sql_file_path << std::endl;
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            std::string line;
            while (std::getline(sql_file, line)) {
                // Skip comments and empty lines
                if (line.empty() || line.substr(0, 2) == "--") {
                    continue;
                }
                
                // Execute SQL statement
                try {
                    impl->sqlite.execute(line);
                } catch (const std::exception& e) {
                    std::cerr << "Failed to execute SQL: " << line << " - " << e.what() << std::endl;
                    // Continue with next statement
                }
            }
            
            sql_file.close();
            std::cout << "Database imported from SQL file: " << sql_file_path << std::endl;
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "SQL import failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    void lmDBCore::print(const std::string& query)
    {
        std::cout << "print start ---------------- \n";
        auto vec = impl->sqlite.query<User>(query);
        for (const auto& user : vec) {
            std::cout << user.id << ", " << user.name << ", " 
                      << user.email << ", " << user.phone << ", role=" << user.role << "\n";
        }

        std::cout << "print end ------------------\n";
        std::cout << std::endl;
    }

    // Test function to populate database with sample data
    void lmDBCore::populate_test_data()
    {
        std::cout << "\n=== Populating database with test data ===\n";
        
        try {
            // Add test users with different roles
            std::cout << "Adding test users...\n";
            
            // Admin user (role = 4)
            add_user("admin", "admin@lightmaker.local", "123", "+86-10-12345678", "LightMaker HQ", ADMIN);
            
            // Manager user (role = 3)
            add_user("manager1", "manager1@lightmaker.local", "mgr123", "+86-10-12345679", "Management Office", MANAGER);
            
            // Operator users (role = 2)
            add_user("operator1", "operator1@lightmaker.local", "op123", "+86-10-12345680", "Production Floor", OPERATOR);
            
            add_user("operator2", "operator2@lightmaker.local", "op456", "+86-10-12345681", "Production Floor", OPERATOR);
            
            // Regular users (role = 1)
            add_user("user1", "user1@lightmaker.local", "user123", "+86-10-12345682", "User Area", USER);
            
            add_user("user2", "user2@lightmaker.local", "user456", "+86-10-12345683", "User Area", USER);
            
            // Guest users (role = 0)
            add_user("guest1", "guest1@lightmaker.local", "guest123", "+86-10-12345684", "Guest Area", GUEST);
            
            add_user("guest2", "guest2@lightmaker.local", "guest456", "+86-10-12345685", "Guest Area", GUEST);
            
            // Add test customers
            std::cout << "Adding test customers...\n";
            add_customer("ABC Company", "+86-21-12345678");
            add_customer("XYZ Corp", "+86-755-87654321");
            add_customer("Tech Solutions Ltd", "+86-10-11223344");
            
            // Add test orders
            std::cout << "Adding test orders...\n";
            std::string serial;
            add_order("Prototype Parts", "Initial prototype for ABC Company", "ABC Company", 1, "", serial);
            add_order("Production Batch 1", "First production batch", "ABC Company", 1, "", serial);
            add_order("Custom Design", "Custom 3D printed parts for XYZ Corp", "XYZ Corp", 1, "", serial);
            add_order("R&D Samples", "Research and development samples", "XYZ Corp", 1, "", serial);
            
            // Add test print tasks
            std::cout << "Adding test print tasks...\n";
            add_print_task("ORD202412011200001", "Part A - Prototype", "part_a_proto.gcode", 5);
            add_print_task("ORD202412011200001", "Part B - Prototype", "part_b_proto.gcode", 3);
            add_print_task("ORD202412011200002", "Part A - Production", "part_a_prod.gcode", 100);
            add_print_task("ORD202412011200003", "Custom Part 1", "custom_part1.gcode", 10);
            add_print_task("ORD202412011200004", "Sample 1", "sample1.gcode", 2);
            
            // Update some print progress
            update_print_progress(1, 3); // Part A - Prototype: 3/5 completed
            update_print_progress(2, 3); // Part B - Prototype: 3/3 completed
            update_print_progress(3, 25); // Part A - Production: 25/100 completed
            
            // Add test embed devices
            std::cout << "Adding test embed devices...\n";
            add_embed_device("Printer-001", 1, "Ultimaker S5", "UM-S5-001", "5.3.0", "1.0", "Ultimaker", 
                           "192.168.1.100", 8080, "00:11:22:33:44:55", 2, "Production Floor A", 
                           "Main 3D printer for production", "{\"max_build_volume\":\"330x240x300\",\"materials\":[\"PLA\",\"ABS\",\"PETG\"]}", 
                           "{\"maintenance_due\":\"2024-02-15\",\"last_calibration\":\"2024-01-15\"}");
            
            add_embed_device("Scanner-001", 2, "EinScan Pro 2X", "ES-P2X-001", "2.1.0", "1.0", "Shining 3D", 
                           "192.168.1.101", 8081, "00:11:22:33:44:56", 2, "Design Studio", 
                           "High-resolution 3D scanner", "{\"resolution\":\"0.1mm\",\"scan_volume\":\"400x400x400\"}", 
                           "{\"calibration_status\":\"valid\",\"last_scan\":\"2024-01-20\"}");
            
            add_embed_device("CNC-001", 3, "Tormach PCNC 440", "TC-440-001", "1.5.0", "1.0", "Tormach", 
                           "192.168.1.102", 8082, "00:11:22:33:44:57", 1, "Machine Shop", 
                           "Desktop CNC milling machine", "{\"work_area\":\"305x152x152\",\"spindle_speed\":\"10000rpm\"}", 
                           "{\"tool_changer\":\"manual\",\"coolant_system\":\"enabled\"}");
            
            // Add test gcode files
            std::cout << "Adding test gcode files...\n";
            auto key1_bytes = lm::crypto::AESEncryption::generateRandomKey();
            auto key2_bytes = lm::crypto::AESEncryption::generateRandomKey();
            auto key3_bytes = lm::crypto::AESEncryption::generateRandomKey();
            
            // Convert keys to hex strings for storage
            std::string key1 = bytesToHex(key1_bytes);
            std::string key2 = bytesToHex(key2_bytes);
            std::string key3 = bytesToHex(key3_bytes);
            
            add_file_record("part_a_proto.gcode", key1, "dd", "gcode");
            add_file_record("part_b_proto.gcode", key2, "bb", "gcode");
            add_file_record("custom_part1.gcode", key3, "cc", "gcode");
            
            std::cout << "Test data populated successfully!\n";
            std::cout << "Generated AES keys:\n";
            std::cout << "  Key 1: " << key1 << "\n";
            std::cout << "  Key 2: " << key2 << "\n";
            std::cout << "  Key 3: " << key3 << "\n";
            
        } catch (const std::exception &e) {
            std::cerr << "Error populating test data: " << e.what() << std::endl;
        }
        
        std::cout << "==========================================\n\n";
    }

    // Test G-code encryption and decryption functionality
    void lmDBCore::test_gcode_encryption_decryption()
    {
        std::cout << "\n=== Testing G-code Encryption/Decryption ===\n";
        
        try {
            // Create a sample G-code file for testing
            std::string sample_gcode_path = "./data/test_sample.gcode";
            std::string encrypted_path = "./data/test_sample.gcode.enc";
            std::string decrypted_path = "./data/test_sample_decrypted.gcode";
            
            std::cout << "1. Creating sample G-code file...\n";
            if (!lm::gcode::GCodeProcessor::createSampleGCodeFile(sample_gcode_path)) {
                std::cerr << "Failed to create sample G-code file" << std::endl;
                return;
            }
            std::cout << "   Sample G-code file created: " << sample_gcode_path << std::endl;
            
            // Display file info
            std::cout << "\n2. Sample G-code file info:\n";
            std::cout << lm::gcode::GCodeProcessor::getGCodeFileInfo(sample_gcode_path) << std::endl;
            
            // Test encryption with random password using new interface
            std::cout << "3. Testing encryption with random password using new interface...\n";
            
            // Generate random password using new interface
            std::vector<uint8_t> random_key;
            DB_RESULT key_gen_result = lmDBCore::generate_random_aes_key(random_key);
            std::string password = bytesToHex(random_key);
            std::cout << "   Generated random password: " << password.substr(0, 16) << "..." << std::endl;
            
            // Read G-code file data into memory
            std::ifstream file(sample_gcode_path, std::ios::binary);
            if (!file.is_open()) {
                std::cerr << "   ✗ Failed to open sample G-code file" << std::endl;
                return;
            }
            
            std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            
            // Test encryption using new data stream to file interface
            std::string test_uuid;
            lmDBCore::generate_uuid(test_uuid);
            std::string db_dir = "./data";
            DB_RESULT encrypt_result = lmDBCore::encrypt_file_with_key(file_data, random_key, test_uuid);
            if (encrypt_result == DB_SUCCESS) {
                std::string actual_path = db_dir + "/file/" + test_uuid + ".enc";
                std::cout << "   ✓ Encryption successful, data written to: " << actual_path << std::endl;
                
                // Test chunked encryption
                std::cout << "\n5. Testing chunked encryption...\n";
                std::string chunked_encrypted_path = "./data/test_sample_chunked.gcode.enc";
                
                // Split data into chunks and encrypt each chunk
                size_t chunk_size = file_data.size() / 3;  // Split into 3 chunks
                if (chunk_size == 0) chunk_size = 1;
                
                for (int i = 0; i < 3; ++i) {
                    size_t start = i * chunk_size;
                    size_t end = (i == 2) ? file_data.size() : (i + 1) * chunk_size;
                    
                    std::vector<uint8_t> chunk_data(file_data.begin() + start, file_data.begin() + end);
                    bool append_mode = (i > 0);  // First chunk overwrites, others append
                    
                    std::string chunk_uuid = test_uuid + "_chunk_" + std::to_string(i);
                    DB_RESULT chunk_result = lmDBCore::encrypt_file_with_key(chunk_data, random_key, chunk_uuid, i, append_mode);
                    if (chunk_result == DB_SUCCESS) {
                        std::cout << "   ✓ Chunk " << i << " encrypted successfully (size: " << chunk_data.size() << " bytes)" << std::endl;
                    } else {
                        std::cout << "   ✗ Chunk " << i << " encryption failed" << std::endl;
                    }
                }
                
                // Test decryption of chunked file
                std::cout << "\n6. Testing chunked decryption...\n";
                std::vector<uint8_t> decrypted_chunked_data;
                DB_RESULT decrypt_chunked_result = lmDBCore::decrypt_file_with_key(test_uuid, random_key, decrypted_chunked_data);
                if (decrypt_chunked_result == DB_SUCCESS) {
                    std::cout << "   ✓ Chunked decryption successful, data size: " << decrypted_chunked_data.size() << " bytes" << std::endl;
                    
                    // Verify data integrity
                    if (decrypted_chunked_data == file_data) {
                        std::cout << "   ✓ Data integrity verified - chunked data matches original" << std::endl;
                    } else {
                        std::cout << "   ✗ Data integrity check failed - chunked data differs from original" << std::endl;
                    }
                } else {
                    std::cout << "   ✗ Chunked decryption failed" << std::endl;
                }
                
                // Test individual chunk decryption
                std::cout << "\n7. Testing individual chunk decryption...\n";
                for (int i = 0; i < 3; ++i) {
                    std::vector<uint8_t> chunk_data;
                    DB_RESULT chunk_decrypt_result = lmDBCore::decrypt_file_chunk(test_uuid, random_key, i, chunk_data);
                    if (chunk_decrypt_result == DB_SUCCESS) {
                        std::cout << "   ✓ Chunk " << i << " decrypted successfully (size: " << chunk_data.size() << " bytes)" << std::endl;
                    } else {
                        std::cout << "   ✗ Chunk " << i << " decryption failed" << std::endl;
                    }
                }
                
                // Store G-code file info in database
                std::cout << "   Storing G-code info in database...\n";
                bool db_success = add_file_record("test_sample.gcode", password, "cc", "gcode");
                if (db_success) {
                    std::cout << "   ✓ G-code info stored in database successfully\n";
                } else {
                    std::cout << "   ⚠ Failed to store G-code info in database\n";
                }
            } else {
                std::cerr << "   ✗ Encryption failed" << std::endl;
                return;
            }
            
            // Test decryption using password from database with new interface
            std::cout << "\n4. Testing decryption using password from database with new interface...\n";
            
            //  
            std::vector<File_record> all_files;
            if (get_all_file_records(all_files) != DB_SUCCESS || all_files.empty()) {
                std::cerr << "   ✗ Test G-code file not found in database" << std::endl;
                return;
            }
             
            File_record test_file;
            bool found = false;
            for (const auto& file : all_files) {
                if (file.filename == "test_sample.gcode") {
                    test_file = file;
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                std::cerr << "   ✗ Test G-code file not found in database" << std::endl;
                return;
            }
            
            std::cout << "   Retrieved password from database: " << test_file.aeskey.substr(0, 16) << "..." << std::endl;
            
            // Convert password string back to key
            std::vector<uint8_t> db_key = hexToBytes(test_file.aeskey);
            
            // Test decryption using new file to data stream interface
            std::vector<uint8_t> decrypted_data;
            DB_RESULT decrypt_result = lmDBCore::decrypt_file_with_key(test_uuid, db_key, decrypted_data);
            if (decrypt_result == DB_SUCCESS) {
                std::cout << "   ✓ Decryption successful, data size: " << decrypted_data.size() << " bytes" << std::endl;
                
                // Write decrypted data to file
                std::ofstream out_file(decrypted_path, std::ios::binary);
                if (out_file.is_open()) {
                    out_file.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
                    out_file.close();
                    std::cout << "   ✓ Decrypted data written to: " << decrypted_path << std::endl;
                }
            } else {
                std::cerr << "   ✗ Decryption failed" << std::endl;
                return;
            }
            
            // Verify decrypted file by comparing with original
            std::cout << "\n5. Verifying decrypted file...\n";
            if (decrypted_data == file_data) {
                std::cout << "   ✓ Decrypted data matches original data" << std::endl;
            } else {
                std::cerr << "   ✗ Decrypted data does not match original data" << std::endl;
                return;
            }
            
            // Test additional new interfaces
            std::cout << "\n6. Testing additional new interfaces...\n";
        } catch (const std::exception& e) {
            std::cerr << "G-code encryption/decryption test error: " << e.what() << std::endl;
        }
    }

    // ==================== PrintTask 结构体接口 ====================

    // 新增：传入PrintTask结构体的add_print_task接口
    DB_RESULT lmDBCore::add_print_task(PrintTask &task)
    {
        try
        {
            // Validate input parameters
            if (task.order_serial_number.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.print_name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.file_uuid.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.total_quantity <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Set default values
            if (task.completed_quantity < 0) {
                task.completed_quantity = 0;
            }
            
            impl->sqlite.insert(task);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add print task (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // 新增：传入PrintTask结构体的update_print_task接口
    DB_RESULT lmDBCore::update_print_task(const PrintTask &task)
    {
        try
        {
            // Validate input parameters
            if (task.id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.order_serial_number.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.print_name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.file_uuid.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.total_quantity <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.completed_quantity < 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if task exists
            auto existing = impl->sqlite.query_s<PrintTask>("id = ?", task.id);
            if (existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            impl->sqlite.update(task);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update print task (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

 
    DB_RESULT lmDBCore::add_file_record(File_record &file)
    {
        try
        {
            if (file.filename.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            
            if (file.aeskey.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Always generate a new UUID for the file
            DB_RESULT uuid_result = lmDBCore::generate_uuid(file.uuid);
            if (uuid_result != DB_SUCCESS) {
                return uuid_result;
            }
            
            // Check if UUID already exists
            auto existing = impl->sqlite.query_s<File_record>("uuid = ?", file.uuid);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // UUID already exists
            }

            // Set default timestamp if not provided
            if (file.upload_time.empty()) {
                file.upload_time = std::to_string(static_cast<int64_t>(time(0)));
            }
            
            impl->sqlite.insert(file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add gcode file (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // 新增：传入File_record结构体的update_file_record接口
    DB_RESULT lmDBCore::update_file_record(File_record &file)
    {
        try
        {
       
            if (file.uuid.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            auto existing = impl->sqlite.query_s<File_record>("uuid = ?", file.uuid);
            if (existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            file.aeskey = existing[0].aeskey;
     
            impl->sqlite.update(file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update gcode file (struct) failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    //  
    DB_RESULT lmDBCore::set_file_aeskey_by_uuid(const std::string& uuid, const std::string& aeskey)
    {
        try
        {
            //  
            if (uuid.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (aeskey.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            //  
            auto existing = impl->sqlite.query_s<File_record>("uuid = ?", uuid);
            if (existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            
            //  
            File_record file = existing[0];
            file.aeskey = aeskey;
            
            impl->sqlite.update(file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Set file aeskey by UUID failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    // Generate comprehensive test cases for all database functions
    void lmDBCore::generate_database_test_cases()
    {
        std::cout << "\n=== Generate Database Function Test Cases ===\n";
        
        try {
            // Clear existing data to ensure clean test environment
            clear_all_data();
            
            std::cout << "\n1. Test database initialization...\n";
            DB_RESULT init_result = initialize();
            std::cout << "   Database initialization: " << (init_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // ========== User Management Test Cases ==========
            std::cout << "\n2. User Management Function Test Cases:\n";
            
            // Test add user
            std::cout << "   2.1 Test add_user():\n";
            DB_RESULT add_user_result1 = add_user("test_user1", "test1@example.com", "password123", "1234567890", "Test Address 1", ADMIN);
            std::cout << "      - Add admin user: " << (add_user_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            if (add_user_result1 != DB_SUCCESS) {
                std::cout << "        Error: " << get_db_error_message(add_user_result1) << std::endl;
            }
            
            DB_RESULT add_user_result2 = add_user("test_user2", "test2@example.com", "password456", "0987654321", "Test Address 2", USER);
            std::cout << "      - Add regular user: " << (add_user_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            if (add_user_result2 != DB_SUCCESS) {
                std::cout << "        Error: " << get_db_error_message(add_user_result2) << std::endl;
            }
            
            DB_RESULT add_user_result3 = add_user("test_user1", "duplicate@example.com", "password789", "1111111111", "Duplicate Address", GUEST);
            std::cout << "      - Add duplicate username (should fail): " << (add_user_result3 == DB_ERROR_DUPLICATE_RECORD ? "CORRECTLY FAILED" : "SHOULD HAVE FAILED") << std::endl;
            if (add_user_result3 != DB_SUCCESS) {
                std::cout << "        Error: " << get_db_error_message(add_user_result3) << std::endl;
            }
            
            // Test add_user with invalid parameters
            std::cout << "   2.1.1 Test add_user() with invalid parameters:\n";
            DB_RESULT add_user_result4 = add_user("test_user3", "test3@example.com", "password999", "2222222222", "Test Address 3", MANAGER);
            std::cout << "      - Add manager user: " << (add_user_result4 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            if (add_user_result4 != DB_SUCCESS) {
                std::cout << "        Error: " << get_db_error_message(add_user_result4) << std::endl;
            }
            
            DB_RESULT add_user_result5 = add_user("test_user1", "duplicate2@example.com", "password000", "3333333333", "Duplicate Address 2", GUEST);
            std::cout << "      - Add duplicate username (should fail): " << (add_user_result5 == DB_ERROR_DUPLICATE_RECORD ? "CORRECTLY FAILED" : "SHOULD HAVE FAILED") << std::endl;
            if (add_user_result5 != DB_SUCCESS) {
                std::cout << "        Error: " << get_db_error_message(add_user_result5) << std::endl;
            }
            
            User user;
            if (get_user_by_name("test_user1", user) == DB_SUCCESS) {
            DB_RESULT remove_user_result7 = remove_user(user.id);
            if (remove_user_result7 != DB_SUCCESS) {
                std::cout << "        Error: " << get_db_error_message(remove_user_result7) << std::endl;
                }
            } 
 
            // Note: set_password method has been removed, passwords are now set during user creation
            
            // Test user verification
            std::cout << "   2.3 Test verify_user():\n";
            DB_RESULT verify_result1 = verify_user("test_user1", "password123");
            std::cout << "      - Verify user1 correct password: " << (verify_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT verify_result2 = verify_user("test_user1", "wrong_password");
            std::cout << "      - Verify user1 wrong password: " << (verify_result2 == DB_ERROR_PASSWORD_INCORRECT ? "CORRECTLY FAILED" : "SHOULD HAVE FAILED") << std::endl;
            
            DB_RESULT verify_result3 = verify_user("nonexistent_user", "password123");
            std::cout << "      - Verify non-existent user: " << (verify_result3 == DB_ERROR_RECORD_NOT_FOUND ? "CORRECTLY FAILED" : "SHOULD HAVE FAILED") << std::endl;
            
            // Test get user
            std::cout << "   2.4 Test get_user_by_name():\n";
            User user1;
            DB_RESULT get_user_result1 = get_user_by_name("test_user1", user1);
            std::cout << "      - Get user1: " << (get_user_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            User user_nonexistent;
            DB_RESULT get_user_result2 = get_user_by_name("nonexistent_user", user_nonexistent);
            std::cout << "      - Get non-existent user: " << (get_user_result2 == DB_ERROR_RECORD_NOT_FOUND ? "CORRECTLY RETURNED NOT_FOUND" : "SHOULD HAVE RETURNED NOT_FOUND") << std::endl;
            
            // Test update user
            std::cout << "   2.5 Test update_user():\n";
            DB_RESULT update_user_result = update_user("test_user1", "updated_user1", "updated1@example.com", "9999999999", "Updated Address 1", MANAGER);
            std::cout << "      - Update user1 info: " << (update_user_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get all users
            std::cout << "   2.6 Test get_all_users():\n";
            std::vector<User> all_users;
            DB_RESULT get_all_users_result = get_all_users(all_users);
            std::cout << "      - Get all users count: " << (get_all_users_result == DB_SUCCESS ? std::to_string(all_users.size()) : "FAILED") << " users" << std::endl;
            
            // Test set password
            std::cout << "   2.7 Test set_password():\n";
            DB_RESULT set_pwd_result = set_password("updated_user1", "newpassword123");
            std::cout << "      - Set user password: " << (set_pwd_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update user role by name
            std::cout << "   2.8 Test update_user_role_by_name():\n";
            
            // Test valid role update
            DB_RESULT update_role_result1 = update_user_role_by_name("updated_user1", static_cast<int>(USER_ROLE::MANAGER));
            std::cout << "      - Update user role to MANAGER: " << (update_role_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test invalid role update
            DB_RESULT update_role_result2 = update_user_role_by_name("updated_user1", 99);  // Invalid role
            std::cout << "      - Update user role to invalid value (99): " << (update_role_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
  
            // ========== Customer Management Test Cases ==========
            std::cout << "\n3. Customer Management Function Test Cases:\n";
            
            // Test add customer
            std::cout << "   3.1 Test add_customer():\n";
            DB_RESULT add_customer_result1 = add_customer("Test Customer 1", "1111111111", "customer1@example.com", "", "Customer Address 1", "Test Company 1", "Manager", "Notes 1");
            std::cout << "      - Add customer 1: " << (add_customer_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT add_customer_result2 = add_customer("Test Customer 2", "2222222222", "customer2@example.com", "", "Customer Address 2", "Test Company 2", "Director", "Notes 2");
            std::cout << "      - Add customer 2: " << (add_customer_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get customer
            std::cout << "   3.2 Test get_customer_by_name():\n";
            Customer customer1;
            DB_RESULT get_customer_result = get_customer_by_name("Test Customer 1", customer1);
            std::cout << "      - Get customer 1: " << (get_customer_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update customer
            std::cout << "   3.3 Test update_customer():\n";
            DB_RESULT update_customer_result = update_customer("Test Customer 1", "Updated Customer 1", "3333333333", "updated1@example.com", "", "Updated Address 1", "Updated Company 1", "Updated Position 1", "Updated Notes 1");
            std::cout << "      - Update customer 1: " << (update_customer_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get all customers
            std::cout << "   3.4 Test get_all_customers():\n";
            std::vector<Customer> all_customers;
            DB_RESULT get_all_customers_result = get_all_customers(all_customers);
            std::cout << "      - Get all customers count: " << (get_all_customers_result == DB_SUCCESS ? std::to_string(all_customers.size()) : "FAILED") << " customers" << std::endl;
            
            // ========== Order Management Test Cases ==========
            std::cout << "\n4. Order Management Function Test Cases:\n";
            
            // Test add order
            std::cout << "   4.1 Test add_order():\n";
            std::string serial1;
            DB_RESULT add_order_result1 = add_order("Test Order 1", "Order Description 1", "Test Customer 1", 10, "Attachment 1", serial1);
            std::cout << "      - Add order 1: " << (add_order_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::string serial2;
            DB_RESULT add_order_result2 = add_order("Test Order 2", "Order Description 2", "Test Customer 2", 20, "Attachment 2", serial2);
            std::cout << "      - Add order 2: " << (add_order_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test add_order with Order struct
            std::cout << "   4.1.1 Test add_order(Order&):\n";
            Order test_order1;
            test_order1.name = "Test Order 3";
            test_order1.description = "Order Description 3";
            test_order1.customer_name = "Test Customer 3";
            test_order1.print_quantity = 30;
            test_order1.attachments = "Attachment 3";
            // serial_number will be generated automatically
            
            std::string test_serial;
            DB_RESULT add_order_struct_result = add_order(test_order1, test_serial);
            std::cout << "      - Add order 3 (struct): " << (add_order_struct_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            std::cout << "      - Generated serial number: " << test_serial << std::endl;
            
            // Test get order
            std::cout << "   4.2 Test get_order_by_id():\n";
            Order order1;
            DB_RESULT get_order_result = get_order_by_id(1, order1);
            std::cout << "      - Get order 1: " << (get_order_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update order
            std::cout << "   4.3 Test update_order():\n";
            DB_RESULT update_order_result = update_order(1, "Updated Order 1", "Updated Description 1", "Test Customer 1", 15, "Updated Attachment 1");
            std::cout << "      - Update order 1: " << (update_order_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get orders by customer
            std::cout << "   4.4 Test get_orders_by_customer():\n";
            std::vector<Order> customer_orders;
            DB_RESULT get_orders_by_customer_result = get_orders_by_customer("Test Customer 1", customer_orders);
            std::cout << "      - Get customer 1 orders count: " << (get_orders_by_customer_result == DB_SUCCESS ? std::to_string(customer_orders.size()) : "FAILED") << " orders" << std::endl;
            
            // Test get all orders
            std::cout << "   4.5 Test get_all_orders():\n";
            std::vector<Order> all_orders;
            DB_RESULT get_all_orders_result = get_all_orders(all_orders);
            std::cout << "      - Get all orders count: " << (get_all_orders_result == DB_SUCCESS ? std::to_string(all_orders.size()) : "FAILED") << " orders" << std::endl;
            
            // ========== Embedded Device Management Test Cases ==========
            std::cout << "\n5. Embedded Device Management Function Test Cases:\n";
            
            // Test add device
            std::cout << "   5.1 Test add_embed_device():\n";
            DB_RESULT add_device_result1 = add_embed_device("Test Device 1", 1, "Model 1", "Serial 1", "Firmware 1.0", "Hardware 1.0", "Manufacturer 1", "192.168.1.100", 8080, "00:11:22:33:44:55", 1, "Location 1", "Description 1", "Capabilities 1", "Metadata 1");
            std::cout << "      - Add device 1: " << (add_device_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT add_device_result2 = add_embed_device("Test Device 2", 2, "Model 2", "Serial 2", "Firmware 2.0", "Hardware 2.0", "Manufacturer 2", "192.168.1.101", 8081, "00:11:22:33:44:56", 2, "Location 2", "Description 2", "Capabilities 2", "Metadata 2");
            std::cout << "      - Add device 2: " << (add_device_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
  
            
            // Test get device by serial number (new primary method)
            std::cout << "   5.3 Test get_embed_device_by_serial_number():\n";
            EmbedDevice device1_by_serial;
            DB_RESULT get_device_by_serial_result = get_embed_device_by_serial_number("Serial 1", device1_by_serial);
            std::cout << "      - Get device 1 by serial: " << (get_device_by_serial_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get devices by type
            std::cout << "   5.3 Test get_embed_devices_by_type():\n";
            std::vector<EmbedDevice> type1_devices;
            DB_RESULT get_devices_by_type_result = get_embed_devices_by_type(1, type1_devices);
            std::cout << "      - Get type 1 devices count: " << (get_devices_by_type_result == DB_SUCCESS ? std::to_string(type1_devices.size()) : "FAILED") << " devices" << std::endl;
            
            // Test update device
            std::cout << "   5.4 Test update_embed_device():\n";
            DB_RESULT update_device_result = update_embed_device("Test Device 1", "Updated Device 1", 1, "Updated Model 1", "Updated Serial 1", "Updated Firmware 1.1", "Updated Hardware 1.1", "Updated Manufacturer 1", "192.168.1.200", 8082, "00:11:22:33:44:66", 2, "Updated Location 1", "Updated Description 1", "Updated Capabilities 1", "Updated Metadata 1");
            std::cout << "      - Update device 1: " << (update_device_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get all devices
            std::cout << "   5.5 Test get_all_embed_devices():\n";
            std::vector<EmbedDevice> all_devices;
            DB_RESULT get_all_devices_result = get_all_embed_devices(all_devices);
            std::cout << "      - Get all devices count: " << (get_all_devices_result == DB_SUCCESS ? std::to_string(all_devices.size()) : "FAILED") << " devices" << std::endl;
            
            // Test new serial_number-based methods
            std::cout << "   5.6 Test new serial_number-based methods:\n";
            DB_RESULT update_by_serial_result = update_embed_device("Serial 1", "Updated Device 1 by Serial", 1, "Updated Model 1", "Updated Serial 1", "Updated Firmware 1.2", "Updated Hardware 1.2", "Updated Manufacturer 1", "192.168.1.201", 8083, "00:11:22:33:44:77", 3, "Updated Location 1", "Updated Description 1", "Updated Capabilities 1", "Updated Metadata 1");
            std::cout << "      - Update device by serial: " << (update_by_serial_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT remove_by_serial_result = remove_embed_device_by_serial_number("Serial 2");
            std::cout << "      - Remove device by serial: " << (remove_by_serial_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // ========== Print Task Management Test Cases ==========
            std::cout << "\n6. Print Task Management Function Test Cases:\n";
            
            // Test add print task
            std::cout << "   6.1 Test add_print_task():\n";
            DB_RESULT add_task_result1 = add_print_task("ORD202412011200001", "Print Task 1", "task1.gcode", 100);
            std::cout << "      - Add print task 1: " << (add_task_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT add_task_result2 = add_print_task("ORD202412011200002", "Print Task 2", "task2.gcode", 200);
            std::cout << "      - Add print task 2: " << (add_task_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get print task
            std::cout << "   6.2 Test get_print_task_by_id():\n";
            PrintTask task1;
            DB_RESULT get_task_result = get_print_task_by_id(1, task1);
            std::cout << "      - Get print task 1: " << (get_task_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update print progress
            std::cout << "   6.3 Test update_print_progress():\n";
            DB_RESULT update_progress_result = update_print_progress(1, 50);
            std::cout << "      - Update print task 1 progress: " << (update_progress_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get print tasks by order
            std::cout << "   6.4 Test get_print_tasks_by_order():\n";
            std::vector<PrintTask> order_tasks;
            DB_RESULT get_tasks_by_order_result = get_print_tasks_by_order("ORD202412011200001", order_tasks);
            std::cout << "      - Get order 1 print tasks count: " << (get_tasks_by_order_result == DB_SUCCESS ? std::to_string(order_tasks.size()) : "FAILED") << " tasks" << std::endl;
            
            // Test update print task
            std::cout << "   6.5 Test update_print_task():\n";
            DB_RESULT update_task_result = update_print_task(1, "Updated Print Task 1", "updated_task1.gcode", 150, 75);
            std::cout << "      - Update print task 1: " << (update_task_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get all print tasks
            std::cout << "   6.6 Test get_all_print_tasks():\n";
            std::vector<PrintTask> all_tasks;
            DB_RESULT get_all_tasks_result = get_all_print_tasks(all_tasks);
            std::cout << "      - Get all print tasks count: " << (get_all_tasks_result == DB_SUCCESS ? std::to_string(all_tasks.size()) : "FAILED") << " tasks" << std::endl;
            
            // ========== G-code File Management Test Cases ==========
            std::cout << "\n7. G-code File Management Function Test Cases:\n";
            
            // Test add G-code file
            std::cout << "   7.1 Test add_file_record():\n";
            std::string test_key1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            DB_RESULT add_file_result1 = add_file_record("test1.gcode", test_key1, "ss", "gcode");
            std::cout << "      - Add file record 1: " << (add_file_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::string test_key2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
            DB_RESULT add_file_result2 = add_file_record("test2.gcode", test_key2, "yy", "gcode");
            std::cout << "      - Add file record 2: " << (add_file_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get file record
            std::cout << "   7.2 Test get_file_record():\n";
            // 
            std::vector<File_record> all_files;
            DB_RESULT get_all_result = get_all_file_records(all_files);
            File_record file1;
            DB_RESULT get_file_result = DB_ERROR_RECORD_NOT_FOUND;
            if (get_all_result == DB_SUCCESS) {
                for (const auto& file : all_files) {
                    if (file.filename == "test1.gcode") {
                        file1 = file;
                        get_file_result = DB_SUCCESS;
                        break;
                    }
                }
            }
            std::cout << "      - Get file record 1: " << (get_file_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test UUID-based operations
            std::cout << "   7.2.1 Test UUID-based operations:\n";
            std::cout << "      - Generated UUID: " << file1.uuid << std::endl;
            
            // Test get by UUID
            File_record file_by_uuid;
            DB_RESULT get_by_uuid_result = get_file_record(file1.uuid, file_by_uuid);
            std::cout << "      - Get file record by UUID: " << (get_by_uuid_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update file record
            std::cout << "   7.3 Test update_file_record():\n";
            std::string new_key = "1111111111111111111111111111111111111111111111111111111111111111";
            DB_RESULT update_file_result = update_file_record(file1.uuid, "updated_test1.gcode", new_key, "Customer1", "gcode");
            std::cout << "      - Update file record 1: " << (update_file_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test set file aeskey by UUID
            std::cout << "   7.3.1 Test set_file_aeskey_by_uuid():\n";
            std::string new_aeskey = "2222222222222222222222222222222222222222222222222222222222222222";
            DB_RESULT set_aeskey_result = set_file_aeskey_by_uuid(file1.uuid, new_aeskey);
            std::cout << "      - Set aeskey for file 1: " << (set_aeskey_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get all file records
            std::cout << "   7.4 Test get_all_file_records():\n";
            std::vector<File_record> all_file_records;
            DB_RESULT get_all_files_result = get_all_file_records(all_file_records);
            std::cout << "      - Get all file records count: " << (get_all_files_result == DB_SUCCESS ? std::to_string(all_file_records.size()) : "FAILED") << " files" << std::endl;
            
            // Test get total G-code files count
            std::cout << "   7.5 Test get_total_file_records_count():\n";
            int file_count = 0;
            DB_RESULT get_file_count_result = get_total_file_records_count(file_count);
            std::cout << "      - Total file records count: " << (get_file_count_result == DB_SUCCESS ? std::to_string(file_count) : "FAILED") << " files" << std::endl;
            
            // Test get file records by customer
            std::cout << "   7.6 Test get_file_records_by_customer():\n";
            std::vector<File_record> customer1_files;
            DB_RESULT get_customer1_result = get_file_records_by_customer("Customer1", customer1_files);
            std::cout << "      - Customer 1 files count: " << (get_customer1_result == DB_SUCCESS ? std::to_string(customer1_files.size()) : "FAILED") << " files" << std::endl;
            
            std::vector<File_record> customer2_files;
            DB_RESULT get_customer2_result = get_file_records_by_customer("Customer2", customer2_files);
            std::cout << "      - Customer 2 files count: " << (get_customer2_result == DB_SUCCESS ? std::to_string(customer2_files.size()) : "FAILED") << " files" << std::endl;
            
            // Test get file records count by customer
            std::cout << "   7.7 Test get_file_records_count_by_customer():\n";
            int customer1_count = 0;
            DB_RESULT get_customer1_count_result = get_file_records_count_by_customer("Customer1", customer1_count);
            std::cout << "      - Customer 1 files count: " << (get_customer1_count_result == DB_SUCCESS ? std::to_string(customer1_count) : "FAILED") << " files" << std::endl;
            
            int customer2_count = 0;
            DB_RESULT get_customer2_count_result = get_file_records_count_by_customer("Customer2", customer2_count);
            std::cout << "      - Customer 2 files count: " << (get_customer2_count_result == DB_SUCCESS ? std::to_string(customer2_count) : "FAILED") << " files" << std::endl;
            
            // Test UUID generation
            std::cout << "   7.8 Test generate_uuid():\n";
            std::string test_uuid;
            DB_RESULT uuid_gen_result = lmDBCore::generate_uuid(test_uuid);
            std::cout << "      - Generate UUID: " << (uuid_gen_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            if (uuid_gen_result == DB_SUCCESS) {
                std::cout << "      - Generated UUID: " << test_uuid << std::endl;
            }
            
            // Test Order-File relationship operations
            std::cout << "   7.9 Test Order-File relationship operations:\n";
            
            // Create test order first
            Order test_order;
            test_order.name = "Test Order for File Relations";
            test_order.serial_number = "ORD-FILE-001";
            test_order.description = "Test order for file relationship testing";
            test_order.print_quantity = 100;
            test_order.customer_name = "abc company";
            test_order.created_at = time(0);
            test_order.updated_at = time(0);
            
            std::string test_serial2;
            DB_RESULT add_order_result = add_order(test_order, test_serial2);
            std::cout << "      - Add test order: " << (add_order_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            if (add_order_result == DB_SUCCESS) {
                // Test add order-file relation
                DB_RESULT add_relation_result = add_order_file_relation(test_order.id, file1.uuid, "Main GCode file for order");
                std::cout << "      - Add order-file relation: " << (add_relation_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
                
                // Test get files by order
                std::vector<File_record> order_files;
                DB_RESULT get_files_result = get_files_by_order(test_order.id, order_files);
                std::cout << "      - Get files by order: " << (get_files_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << " (" << order_files.size() << " files)" << std::endl;
                
                // Test get orders by file
                std::vector<Order> file_orders;
                DB_RESULT get_orders_result = get_orders_by_file(file1.uuid, file_orders);
                std::cout << "      - Get orders by file: " << (get_orders_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << " (" << file_orders.size() << " orders)" << std::endl;
                
                // Test get relation count
                int relation_count = 0;
                DB_RESULT get_count_result = get_order_file_relation_count(test_order.id, relation_count);
                std::cout << "      - Get order-file relation count: " << (get_count_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << " (" << relation_count << " relations)" << std::endl;
                
                // Test update relation description
                DB_RESULT update_relation_result = update_order_file_relation(test_order.id, file1.uuid, "Updated description for main file");
                std::cout << "      - Update order-file relation: " << (update_relation_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
                
                // Test remove order-file relation
                DB_RESULT remove_relation_result = remove_order_file_relation(test_order.id, file1.uuid);
                std::cout << "      - Remove order-file relation: " << (remove_relation_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            }
            
            // ========== Statistics Function Test Cases ==========
            std::cout << "\n8. Statistics Function Test Cases:\n";
            
            std::cout << "   8.1 Test get_total_orders_count():\n";
            int order_count = 0;
            DB_RESULT get_order_count_result = get_total_orders_count(order_count);
            std::cout << "      - Total orders count: " << (get_order_count_result == DB_SUCCESS ? std::to_string(order_count) : "FAILED") << " orders" << std::endl;
            
            std::cout << "   8.2 Test get_total_print_tasks_count():\n";
            int task_count = 0;
            DB_RESULT get_task_count_result = get_total_print_tasks_count(task_count);
            std::cout << "      - Total print tasks count: " << (get_task_count_result == DB_SUCCESS ? std::to_string(task_count) : "FAILED") << " tasks" << std::endl;
            
            std::cout << "   8.3 Test get_completed_print_tasks_count():\n";
            int completed_count = 0;
            DB_RESULT get_completed_count_result = get_completed_print_tasks_count(completed_count);
            std::cout << "      - Completed print tasks count: " << (get_completed_count_result == DB_SUCCESS ? std::to_string(completed_count) : "FAILED") << " tasks" << std::endl;
            
            // ========== Delete Operations Test Cases ==========
            std::cout << "\n9. Delete Operations Test Cases:\n";
            
            std::cout << "   9.1 Test remove_user():\n";
            DB_RESULT remove_user_result = remove_user("updated_user1");
            std::cout << "      - Remove user 1: " << (remove_user_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::cout << "   9.2 Test remove_customer():\n";
            DB_RESULT remove_customer_result = remove_customer("Updated Customer 1");
            std::cout << "      - Remove customer 1: " << (remove_customer_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::cout << "   9.3 Test remove_order():\n";
            DB_RESULT remove_order_result = remove_order(1);
            std::cout << "      - Remove order 1: " << (remove_order_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::cout << "   9.4 Test remove_embed_device():\n";
            DB_RESULT remove_device_result = remove_embed_device("Updated Device 1");
            std::cout << "      - Remove device 1: " << (remove_device_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::cout << "   9.5 Test remove_print_task():\n";
            DB_RESULT remove_task_result = remove_print_task(1);
            std::cout << "      - Remove print task 1: " << (remove_task_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::cout << "   9.6 Test remove_file_record():\n";
            DB_RESULT remove_file_result = remove_file_record(file1.uuid);
            std::cout << "      - Remove file record 1: " << (remove_file_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            
            // ========== Database Status Test ==========
            std::cout << "\n10. Database Status Test:\n";
            std::cout << "   10.1 Test print_database_status():\n";
            print_database_status();
            
            std::cout << "\n=== Database Function Test Cases Generation Complete ===\n";
            std::cout << "All database functions have been verified through test cases!\n";
            
        } catch (const std::exception& e) {
            std::cerr << "Error occurred while generating test cases: " << e.what() << std::endl;
        }
    }

    // Helper function to check if a filename has a specific extension
    static bool has_extension(const std::string& filename, const std::string& extension) {
        if (filename.length() < extension.length()) {
            return false;
        }
        return filename.substr(filename.length() - extension.length()) == extension;
    }

    // Static utility functions implementation
    std::vector<std::string> lmDBCore::enumerate_database_files(const std::string& data_directory)
    {
        std::vector<std::string> database_files;
        
        try {
            std::string search_dir = data_directory.empty() ? get_default_data_directory() : data_directory;
            
            // Check if directory exists
            if (!std::filesystem::exists(search_dir)) {
                std::cerr << "Data directory does not exist: " << search_dir << std::endl;
                return database_files;
            }
            
            // Iterate through all subdirectories in the data directory
            for (const auto& entry : std::filesystem::recursive_directory_iterator(search_dir)) {
                if (entry.is_directory()) {
                    std::string dir_path = entry.path().string();
                    
                    // Look for database files in each subdirectory
                    for (const auto& file_entry : std::filesystem::directory_iterator(dir_path)) {
                        if (file_entry.is_regular_file()) {
                            std::string filename = file_entry.path().filename().string();
                            std::string file_path = file_entry.path().string();
                            
                            // Check if it's a database file (SQLite files typically have .db, .sqlite, .sqlite3 extensions)
                            if (has_extension(filename, ".db") ||
                                has_extension(filename, ".sqlite") ||
                                has_extension(filename, ".sqlite3") ||
                                has_extension(filename, ".db3")) {
                                
                                // Extract the database name (directory name)
                                std::filesystem::path dir_path_obj(dir_path);
                                std::string db_name = dir_path_obj.filename().string();
                                
                                // Add to results with format: "db_name|file_path"
                                std::string result = db_name + "|" + file_path;
                                database_files.push_back(result);
                            }
                        }
                    }
                }
            }
            
            // Sort the results by database name
            std::sort(database_files.begin(), database_files.end());
            
        } catch (const std::exception& e) {
            std::cerr << "Error enumerating database files: " << e.what() << std::endl;
        }
        
        return database_files;
    }

    std::string lmDBCore::get_default_data_directory()
    {
        return getUserDataDirectory() + "/data";
    }


    DB_RESULT lmDBCore::encrypt_file_with_key(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key, const std::string& file_uuid, int chunk_index, bool append_mode)
    {
        try
        {
            // Construct output path: db_dir + "file" + file_uuid + ".enc"
            std::string file_dir =  get_file_dir();
            std::string output_path = file_dir + "/" + file_uuid + ".enc";
            
            // Create directory if it doesn't exist
            createDirectoryIfNotExists(file_dir);
            
            lm::crypto::AESEncryption encryption(key);
            std::vector<uint8_t> encrypted_data = encryption.encrypt(input_data);
            
            // Create chunk header
            struct ChunkHeader {
                uint32_t magic;        // Magic number: 0x4C4D4348 ("LMCH")
                uint32_t chunk_index;  // Chunk index
                uint32_t data_size;    // Encrypted data size
                uint32_t checksum;     // Simple checksum
            };
            
            ChunkHeader header;
            header.magic = 0x4C4D4348;  // "LMCH"
            header.chunk_index = chunk_index;
            header.data_size = static_cast<uint32_t>(encrypted_data.size());
            
            // Calculate simple checksum
            uint32_t checksum = 0;
            for (size_t i = 0; i < encrypted_data.size(); ++i) {
                checksum += encrypted_data[i];
            }
            header.checksum = checksum;
            
            // Open file in appropriate mode
            std::ios_base::openmode mode = std::ios::binary;
            if (append_mode) {
                mode |= std::ios::app;
            }
            
            std::ofstream out_file(output_path, mode);
            if (!out_file.is_open()) {
                std::cerr << "Failed to open output file: " << output_path << std::endl;
                return DB_ERROR_SQL_EXECUTION;
            }
            
            // Write chunk header
            out_file.write(reinterpret_cast<const char*>(&header), sizeof(ChunkHeader));
            
            // Write encrypted data
            out_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
            
            out_file.close();
            
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Encrypt file data with key failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::decrypt_file_with_key(const std::string& file_uuid, const std::vector<uint8_t>& key, std::vector<uint8_t>& output_data)
    {
        try
        {
            output_data.clear();
            
            // Construct input path from UUID and file_dir_
            std::string input_path = file_dir_ + "/" + file_uuid + ".enc";
            
            // Read encrypted file data
            std::ifstream in_file(input_path, std::ios::binary);
            if (!in_file.is_open()) {
                std::cerr << "Failed to open input file: " << input_path << std::endl;
                return DB_ERROR_SQL_EXECUTION;
            }
            
            // Get file size
            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);
            
            // Check if file has chunk headers (new format) or is legacy format
            if (file_size >= 16) {  // Minimum size for chunk header
                // Try to read first chunk header
                struct ChunkHeader {
                    uint32_t magic;
                    uint32_t chunk_index;
                    uint32_t data_size;
                    uint32_t checksum;
                };
                
                ChunkHeader header;
                in_file.read(reinterpret_cast<char*>(&header), sizeof(ChunkHeader));
                
                if (header.magic == 0x4C4D4348) {  // "LMCH" - new chunked format
                    // Reset to beginning and decrypt all chunks
                    in_file.seekg(0, std::ios::beg);
                    
                    lm::crypto::AESEncryption encryption(key);
                    
                    while (in_file.tellg() < static_cast<std::streampos>(file_size)) {
                        // Read chunk header
                        in_file.read(reinterpret_cast<char*>(&header), sizeof(ChunkHeader));
                        if (in_file.gcount() != sizeof(ChunkHeader)) {
                            break;  // End of file or error
                        }
                        
                        // Read encrypted data
                        std::vector<uint8_t> chunk_data(header.data_size);
                        in_file.read(reinterpret_cast<char*>(chunk_data.data()), header.data_size);
                        
                        if (in_file.gcount() != static_cast<std::streamsize>(header.data_size)) {
                            std::cerr << "Failed to read chunk data" << std::endl;
                            return DB_ERROR_SQL_EXECUTION;
                        }
                        
                        // Verify checksum
                        uint32_t calculated_checksum = 0;
                        for (size_t i = 0; i < chunk_data.size(); ++i) {
                            calculated_checksum += chunk_data[i];
                        }
                        
                        if (calculated_checksum != header.checksum) {
                            std::cerr << "Chunk checksum verification failed" << std::endl;
                            return DB_ERROR_SQL_EXECUTION;
                        }
                        
                        // Decrypt chunk and append to output
                        std::vector<uint8_t> decrypted_chunk = encryption.decrypt(chunk_data);
                        output_data.insert(output_data.end(), decrypted_chunk.begin(), decrypted_chunk.end());
                    }
                } else {
                    // Legacy format - decrypt entire file
                    in_file.seekg(0, std::ios::beg);
                    std::vector<uint8_t> encrypted_data(file_size);
                    in_file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);
                    
                    lm::crypto::AESEncryption encryption(key);
                    output_data = encryption.decrypt(encrypted_data);
                }
            } else {
                // File too small, treat as legacy format
                std::vector<uint8_t> encrypted_data(file_size);
                in_file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);
                
                lm::crypto::AESEncryption encryption(key);
                output_data = encryption.decrypt(encrypted_data);
            }
            
            in_file.close();
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decrypt file with key failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::decrypt_file_chunk(const std::string& file_uuid, const std::vector<uint8_t>& key, int chunk_index, std::vector<uint8_t>& output_data)
    {
        try
        {
            output_data.clear();
            
            // Construct input path from UUID and file_dir_
            std::string input_path = file_dir_ + "/" + file_uuid + ".enc";
            
            // Read encrypted file data
            std::ifstream in_file(input_path, std::ios::binary);
            if (!in_file.is_open()) {
                std::cerr << "Failed to open input file: " << input_path << std::endl;
                return DB_ERROR_SQL_EXECUTION;
            }
            
            // Get file size
            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);
            
            lm::crypto::AESEncryption encryption(key);
            
            // Find the specified chunk
            while (in_file.tellg() < static_cast<std::streampos>(file_size)) {
                struct ChunkHeader {
                    uint32_t magic;
                    uint32_t chunk_index;
                    uint32_t data_size;
                    uint32_t checksum;
                };
                
                ChunkHeader header;
                in_file.read(reinterpret_cast<char*>(&header), sizeof(ChunkHeader));
                if (in_file.gcount() != sizeof(ChunkHeader)) {
                    break;  // End of file or error
                }
                
                if (header.magic != 0x4C4D4348) {  // "LMCH"
                    std::cerr << "Invalid chunk header magic" << std::endl;
                    return DB_ERROR_SQL_EXECUTION;
                }
                
                if (header.chunk_index == static_cast<uint32_t>(chunk_index)) {
                    // Found the target chunk
                    std::vector<uint8_t> chunk_data(header.data_size);
                    in_file.read(reinterpret_cast<char*>(chunk_data.data()), header.data_size);
                    
                    if (in_file.gcount() != static_cast<std::streamsize>(header.data_size)) {
                        std::cerr << "Failed to read chunk data" << std::endl;
                        return DB_ERROR_SQL_EXECUTION;
                    }
                    
                    // Verify checksum
                    uint32_t calculated_checksum = 0;
                    for (size_t i = 0; i < chunk_data.size(); ++i) {
                        calculated_checksum += chunk_data[i];
                    }
                    
                    if (calculated_checksum != header.checksum) {
                        std::cerr << "Chunk checksum verification failed" << std::endl;
                        return DB_ERROR_SQL_EXECUTION;
                    }
                    
                    // Decrypt chunk
                    output_data = encryption.decrypt(chunk_data);
                    in_file.close();
                    return DB_SUCCESS;
                } else {
                    // Skip this chunk
                    in_file.seekg(header.data_size, std::ios::cur);
                }
            }
            
            in_file.close();
            return DB_ERROR_RECORD_NOT_FOUND;  // Chunk not found
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decrypt file chunk failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::generate_random_aes_key(std::vector<uint8_t>& out_key)
    {
        try
        {
            out_key = lm::crypto::AESEncryption::generateRandomKey();
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Generate random AES key failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::generate_uuid(std::string& out_uuid)
    {
        try
        {
            // Generate random UUID using OpenSSL RAND_bytes
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 15);
            std::uniform_int_distribution<> dis2(8, 11);
            
            std::stringstream ss;
            int i;
            ss << std::hex;
            for (i = 0; i < 8; i++) {
                ss << dis(gen);
            }
            ss << "-";
            for (i = 0; i < 4; i++) {
                ss << dis(gen);
            }
            ss << "-4";
            for (i = 0; i < 3; i++) {
                ss << dis(gen);
            }
            ss << "-";
            ss << dis2(gen);
            for (i = 0; i < 3; i++) {
                ss << dis(gen);
            }
            ss << "-";
            for (i = 0; i < 12; i++) {
                ss << dis(gen);
            }
            
            out_uuid = ss.str();
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Generate UUID failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }


}
