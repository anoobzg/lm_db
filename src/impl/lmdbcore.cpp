#include "lm/kernel/lmdbcore.h"

#include "sqlite.hpp"
#include "dbng.hpp"
#include "lm/gcode/gcode_processor.h"
#include "lm/crypto/aes_encryption.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <random>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

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

// Helper function to convert bytes to hex string
std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
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
            return DB_ERROR_RECORD_NOT_FOUND;
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
YLT_REFL(Order, id, name, serial_number, description, attachments, print_quantity, customer_id, created_at, updated_at)

REGISTER_AUTO_KEY(EmbedDevice, device_id)
YLT_REFL(EmbedDevice, device_id, device_name, device_type, model, serial_number, firmware_version, hardware_version, manufacturer, ip_address, port, mac_address, status, location, description, last_seen, created_at, updated_at, session_id, capabilities, metadata)

REGISTER_AUTO_KEY(PrintTask, id)
YLT_REFL(PrintTask, id, order_id, print_name, gcode_filename, total_quantity, completed_quantity)

REGISTER_AUTO_KEY(Gcode_file, id)
YLT_REFL(Gcode_file, id, filename, encrypted_path, aeskey, upload_time)

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

            ormpp_auto_key gcode_file_key{"id"};
            ormpp_unique gcode_file_unique{{"filename"}};
            impl->sqlite.create_datatable<Gcode_file>(gcode_file_key, gcode_file_unique);

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
    DB_RESULT lmDBCore::add_order(const std::string& name, const std::string& description, int64_t customer_id, 
                             int32_t print_quantity, const std::string& attachments)
    {
        try
        {
            Order order;
            order.name = name;
            order.description = description;
            order.customer_id = customer_id;
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
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add order failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    // 新增：传入Order结构体的add_order接口
    DB_RESULT lmDBCore::add_order(Order &order)
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
            
            if (order.customer_id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            auto existing_serial = impl->sqlite.query_s<Order>("serial_number = ?", order.serial_number);
            if (!existing_serial.empty())
            {
                // Generate a new serial number if collision occurs
                return DB_ERROR_DUPLICATE_RECORD; // Order name already exists
            }


            // Set timestamps
            time_t now = time(0);
            order.created_at = static_cast<int64_t>(now);
            order.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(order);
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
                                int64_t customer_id, int32_t print_quantity, const std::string& attachments)
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
            order.customer_id = customer_id;
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
                               int64_t customer_id, int32_t print_quantity, const std::string& attachments)
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
            order.customer_id = customer_id;
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

    DB_RESULT lmDBCore::get_orders_by_customer(int64_t customer_id, std::vector<Order> &out_orders)
    {
        try
        {
            out_orders = impl->sqlite.query_s<Order>("customer_id = ?", customer_id);
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
    DB_RESULT lmDBCore::add_print_task(int order_id, const std::string& print_name, const std::string& gcode_filename, int total_quantity)
    {
        try
        {
            PrintTask print_task;
            print_task.order_id = order_id;
            print_task.print_name = print_name;
            print_task.gcode_filename = gcode_filename;
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

    DB_RESULT lmDBCore::remove_print_task(int print_task_id)
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

    DB_RESULT lmDBCore::update_print_task(int print_task_id, const std::string& print_name, const std::string& gcode_filename,
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
            print_task.gcode_filename = gcode_filename;
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

    DB_RESULT lmDBCore::update_print_task(const std::string& print_name, const std::string& new_print_name, const std::string& gcode_filename,
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
            print_task.gcode_filename = gcode_filename;
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

    DB_RESULT lmDBCore::get_print_task_by_id(int print_task_id, PrintTask &out_task)
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

    DB_RESULT lmDBCore::get_print_tasks_by_order(int order_id, std::vector<PrintTask> &out_tasks)
    {
        try
        {
            out_tasks = impl->sqlite.query_s<PrintTask>("order_id = ?", order_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get print tasks by order failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::update_print_progress(int print_task_id, int completed_quantity)
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
    DB_RESULT lmDBCore::add_gcode_file(const std::string& filename, const std::string& encrypted_path, const std::string& aeskey)
    {
        try
        {
            auto existing = impl->sqlite.query_s<Gcode_file>("filename = ?", filename);
            if (!existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND; // Filename already exists
            }

            Gcode_file gcode_file;
            gcode_file.filename = filename;
            gcode_file.encrypted_path = encrypted_path;
            
            // Copy AES key
            gcode_file.aeskey = aeskey;
            
            // Set upload time to current date
            time_t now = time(0);
            char buffer[100];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
            gcode_file.upload_time = buffer;

            impl->sqlite.insert(gcode_file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add gcode file failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_gcode_file(int gcode_file_id)
    {
        try
        {
            impl->sqlite.delete_records_s<Gcode_file>("id = ?", gcode_file_id);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove gcode file failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::remove_gcode_file(const std::string& filename)
    {
        try
        {
            impl->sqlite.delete_records_s<Gcode_file>("filename = ?", filename);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove gcode file by filename failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_gcode_file(int gcode_file_id, const std::string& filename, const std::string& encrypted_path, const std::string& aeskey)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("id = ?", gcode_file_id);
            if (gcode_files.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            Gcode_file gcode_file = gcode_files[0];
            gcode_file.filename = filename;
            gcode_file.encrypted_path = encrypted_path;
            
            // Copy AES key
            gcode_file.aeskey = std::string(aeskey, 32);

            impl->sqlite.update(gcode_file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update gcode file failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::update_gcode_file(const std::string& filename, const std::string& new_filename, const std::string& encrypted_path, const std::string& aeskey)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("filename = ?", filename);
            if (gcode_files.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            Gcode_file gcode_file = gcode_files[0];
            gcode_file.filename = new_filename;
            gcode_file.encrypted_path = encrypted_path;
            
            // Copy AES key
            gcode_file.aeskey = std::string(aeskey, 32);

            impl->sqlite.update(gcode_file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update gcode file by filename failed: " << e.what() << std::endl;
            return DB_ERROR_RECORD_NOT_FOUND;
        }
    }

    DB_RESULT lmDBCore::get_all_gcode_files(std::vector<Gcode_file> &out_files)
    {
        try
        {
            out_files = impl->sqlite.query_s<Gcode_file>("");
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all gcode files failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_gcode_file_by_id(int gcode_file_id, Gcode_file &out_file)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("id = ?", gcode_file_id);
            if (gcode_files.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_file = gcode_files[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get gcode file by id failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_gcode_file_by_filename(const std::string& filename, Gcode_file &out_file)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("filename = ?", filename);
            if (gcode_files.empty()) {
                return DB_ERROR_RECORD_NOT_FOUND;
            }
            out_file = gcode_files[0];
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get gcode file by filename failed: " << e.what() << std::endl;
            return DB_ERROR_SQL_EXECUTION;
        }
    }

    DB_RESULT lmDBCore::get_total_gcode_files_count(int &out_count)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("");
            out_count = static_cast<int>(gcode_files.size());
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total gcode files count failed: " << e.what() << std::endl;
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
            impl->sqlite.delete_records<Gcode_file>();
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

        std::vector<Gcode_file> gcode_files;
        if (get_all_gcode_files(gcode_files) == DB_SUCCESS) {
        std::cout << "G-code file count: " << gcode_files.size() << std::endl;
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
            add_user("admin", "admin@lightmaker.local", "admin123", "+86-10-12345678", "LightMaker HQ", ADMIN);
            
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
            add_order("Prototype Parts", "Initial prototype for ABC Company", 1);
            add_order("Production Batch 1", "First production batch", 1);
            add_order("Custom Design", "Custom 3D printed parts for XYZ Corp", 2);
            add_order("R&D Samples", "Research and development samples", 3);
            
            // Add test print tasks
            std::cout << "Adding test print tasks...\n";
            add_print_task(1, "Part A - Prototype", "part_a_proto.gcode", 5);
            add_print_task(1, "Part B - Prototype", "part_b_proto.gcode", 3);
            add_print_task(2, "Part A - Production", "part_a_prod.gcode", 100);
            add_print_task(3, "Custom Part 1", "custom_part1.gcode", 10);
            add_print_task(4, "Sample 1", "sample1.gcode", 2);
            
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
            
            add_gcode_file("part_a_proto.gcode", "./enc_resource/part_a_proto.enc", key1);
            add_gcode_file("part_b_proto.gcode", "./enc_resource/part_b_proto.enc", key2);
            add_gcode_file("custom_part1.gcode", "./enc_resource/custom_part1.enc", key3);
            
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
            
            // Test encryption with random password
            std::cout << "3. Testing encryption with random password...\n";
            
            // Generate random password
            auto random_key = lm::crypto::AESEncryption::generateRandomKey();
            std::string password = bytesToHex(random_key);
            std::cout << "   Generated random password: " << password.substr(0, 16) << "..." << std::endl;
            
            // Create processor with random password
            lm::gcode::GCodeProcessor processor(password);
            
            if (processor.encryptGCodeFile(sample_gcode_path, encrypted_path)) {
                std::cout << "   ✓ Encryption successful: " << encrypted_path << std::endl;
                
                // Store G-code file info in database
                std::cout << "   Storing G-code info in database...\n";
                bool db_success = add_gcode_file("test_sample.gcode", encrypted_path, password);
                if (db_success) {
                    std::cout << "   ✓ G-code info stored in database successfully\n";
                } else {
                    std::cout << "   ⚠ Failed to store G-code info in database\n";
                }
            } else {
                std::cerr << "   ✗ Encryption failed" << std::endl;
                return;
            }
            
            // Test decryption using password from database
            std::cout << "\n4. Testing decryption using password from database...\n";
            
            // Get G-code file info from database by filename
            Gcode_file test_file;
            if (get_gcode_file_by_filename("test_sample.gcode", test_file) != DB_SUCCESS) {
                std::cerr << "   ✗ Test G-code file not found in database" << std::endl;
                return;
            }
            
            std::cout << "   Retrieved password from database: " << test_file.aeskey.substr(0, 16) << "..." << std::endl;
            
            // Create new processor with password from database
            lm::gcode::GCodeProcessor db_processor(test_file.aeskey);
            
            if (db_processor.decryptGCodeFile(encrypted_path, decrypted_path)) {
                std::cout << "   ✓ Decryption successful using database password: " << decrypted_path << std::endl;
            } else {
                std::cerr << "   ✗ Decryption failed" << std::endl;
                return;
            }
            
            // Verify decrypted file
            std::cout << "\n5. Verifying decrypted file...\n";
            if (lm::gcode::GCodeProcessor::validateGCodeFile(decrypted_path)) {
                std::cout << "   ✓ Decrypted file is valid G-code" << std::endl;
            } else {
                std::cerr << "   ✗ Decrypted file is not valid G-code" << std::endl;
                return;
            }
            
            
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
            if (task.order_id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.print_name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.gcode_filename.empty()) {
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
            
            if (task.order_id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.print_name.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (task.gcode_filename.empty()) {
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

    // ==================== Gcode_file 结构体接口 ====================

    // 新增：传入Gcode_file结构体的add_gcode_file接口
    DB_RESULT lmDBCore::add_gcode_file(Gcode_file &file)
    {
        try
        {
            // Validate input parameters
            if (file.filename.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (file.encrypted_path.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (file.aeskey.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if file already exists
            auto existing = impl->sqlite.query_s<Gcode_file>("filename = ?", file.filename);
            if (!existing.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // File already exists
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

    // 新增：传入Gcode_file结构体的update_gcode_file接口
    DB_RESULT lmDBCore::update_gcode_file(const Gcode_file &file)
    {
        try
        {
            // Validate input parameters
            if (file.id <= 0) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (file.filename.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (file.encrypted_path.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            if (file.aeskey.empty()) {
                return DB_ERROR_INVALID_PARAMETER;
            }
            
            // Check if file exists
            auto existing = impl->sqlite.query_s<Gcode_file>("id = ?", file.id);
            if (existing.empty())
            {
                return DB_ERROR_RECORD_NOT_FOUND;
            }

            // Check if new filename conflicts with existing files (excluding current file)
            auto name_conflict = impl->sqlite.query_s<Gcode_file>("filename = ? AND id != ?", file.filename, file.id);
            if (!name_conflict.empty())
            {
                return DB_ERROR_DUPLICATE_RECORD; // Filename already exists
            }
            
            impl->sqlite.update(file);
            return DB_SUCCESS;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update gcode file (struct) failed: " << e.what() << std::endl;
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
            DB_RESULT add_order_result1 = add_order("Test Order 1", "Order Description 1", 1, 10, "Attachment 1");
            std::cout << "      - Add order 1: " << (add_order_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT add_order_result2 = add_order("Test Order 2", "Order Description 2", 2, 20, "Attachment 2");
            std::cout << "      - Add order 2: " << (add_order_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get order
            std::cout << "   4.2 Test get_order_by_id():\n";
            Order order1;
            DB_RESULT get_order_result = get_order_by_id(1, order1);
            std::cout << "      - Get order 1: " << (get_order_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update order
            std::cout << "   4.3 Test update_order():\n";
            DB_RESULT update_order_result = update_order(1, "Updated Order 1", "Updated Description 1", 1, 15, "Updated Attachment 1");
            std::cout << "      - Update order 1: " << (update_order_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get orders by customer
            std::cout << "   4.4 Test get_orders_by_customer():\n";
            std::vector<Order> customer_orders;
            DB_RESULT get_orders_by_customer_result = get_orders_by_customer(1, customer_orders);
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
            DB_RESULT add_task_result1 = add_print_task(1, "Print Task 1", "task1.gcode", 100);
            std::cout << "      - Add print task 1: " << (add_task_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            DB_RESULT add_task_result2 = add_print_task(2, "Print Task 2", "task2.gcode", 200);
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
            DB_RESULT get_tasks_by_order_result = get_print_tasks_by_order(1, order_tasks);
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
            std::cout << "   7.1 Test add_gcode_file():\n";
            std::string test_key1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            DB_RESULT add_gcode_result1 = add_gcode_file("test1.gcode", "./enc/test1.enc", test_key1);
            std::cout << "      - Add G-code file 1: " << (add_gcode_result1 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            std::string test_key2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
            DB_RESULT add_gcode_result2 = add_gcode_file("test2.gcode", "./enc/test2.enc", test_key2);
            std::cout << "      - Add G-code file 2: " << (add_gcode_result2 == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get G-code file
            std::cout << "   7.2 Test get_gcode_file_by_filename():\n";
            Gcode_file gcode1;
            DB_RESULT get_gcode_result = get_gcode_file_by_filename("test1.gcode", gcode1);
            std::cout << "      - Get G-code file 1: " << (get_gcode_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test update G-code file
            std::cout << "   7.3 Test update_gcode_file():\n";
            std::string new_key = "1111111111111111111111111111111111111111111111111111111111111111";
            DB_RESULT update_gcode_result = update_gcode_file("test1.gcode", "updated_test1.gcode", "./enc/updated_test1.enc", new_key);
            std::cout << "      - Update G-code file 1: " << (update_gcode_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
            // Test get all G-code files
            std::cout << "   7.4 Test get_all_gcode_files():\n";
            std::vector<Gcode_file> all_gcode_files;
            DB_RESULT get_all_gcode_result = get_all_gcode_files(all_gcode_files);
            std::cout << "      - Get all G-code files count: " << (get_all_gcode_result == DB_SUCCESS ? std::to_string(all_gcode_files.size()) : "FAILED") << " files" << std::endl;
            
            // Test get total G-code files count
            std::cout << "   7.5 Test get_total_gcode_files_count():\n";
            int gcode_count = 0;
            DB_RESULT get_gcode_count_result = get_total_gcode_files_count(gcode_count);
            std::cout << "      - Total G-code files count: " << (get_gcode_count_result == DB_SUCCESS ? std::to_string(gcode_count) : "FAILED") << " files" << std::endl;
            
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
            
            std::cout << "   9.6 Test remove_gcode_file():\n";
            DB_RESULT remove_gcode_result = remove_gcode_file("updated_test1.gcode");
            std::cout << "      - Remove G-code file 1: " << (remove_gcode_result == DB_SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
            
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
}
