#pragma once
#include "lm/export.h"
#include <string>
#include <vector>
#include <ctime>
#include <chrono>


enum  USER_ROLE
{
    GUEST = 0,
    USER = 1,
    OPERATOR = 2,
    MANAGER = 3,
    ADMIN = 4
};



// Database operation result codes
enum DB_RESULT
{
    DB_SUCCESS = 0,                    // Operation successful
    DB_ERROR_DATABASE_CONNECTION = 1,  // Database connection error
    DB_ERROR_SQL_EXECUTION = 2,        // SQL execution error
    DB_ERROR_RECORD_NOT_FOUND = 3,     // Record not found
    DB_ERROR_DUPLICATE_RECORD = 4,     // Duplicate record (unique constraint violation)
    DB_ERROR_INVALID_PARAMETER = 5,    // Invalid parameter
    DB_ERROR_PERMISSION_DENIED = 6,    // Permission denied
    DB_ERROR_FOREIGN_KEY_CONSTRAINT = 7, // Foreign key constraint violation
    DB_ERROR_DATABASE_LOCKED = 8,      // Database is locked
    DB_ERROR_DISK_FULL = 9,            // Disk full
    DB_ERROR_OLD_PASSWORD_INCORRECT = 10, // Old password is incorrect (for change_password)
    DB_ERROR_PASSWORD_INCORRECT = 11,  // Password is incorrect (for verify_user)
    DB_ERROR_UNKNOWN = 99              // Unknown error
};

// Helper function to get error message from error code
const char* get_db_error_message(DB_RESULT error_code);

// User data structure (matches user_service.proto)
struct User
{
    int64_t id;                 // Auto-increment primary key
    std::string name;
    std::string email;
    std::string phone;
    std::string address;
    std::string password;       // Stored separately for security
    
    // Permission system (matches proto)
    int role;                   // UserRole enum value (0=GUEST, 1=USER, 2=OPERATOR, 3=MANAGER, 4=ADMIN)
    std::string permissions;    // JSON string of permissions array
    std::string groups;         // JSON string of groups array
    
    int64_t created_at;
    int64_t updated_at;

    User() = default;
    User(const std::string &name, const std::string &email, 
         const std::string &phone = "", const std::string &address = "", int role = 1)
        : name(name), email(email), phone(phone), address(address), role(role) {
        // Set default timestamps
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        created_at = static_cast<int64_t>(time_t);
        updated_at = created_at;
    }
};

// Customer data structure (matches customer_service.proto)
struct Customer
{
    int64_t id;                 // Auto-increment primary key
    std::string name;           // Customer name
    std::string phone;          // Contact phone number
    std::string email;          // Email address
    std::string avatar_image;   // Avatar image path or base64 encoding
    std::string address;        // Address
    std::string company;        // Company name
    std::string position;       // Position/title
    std::string notes;          // Notes/remarks
    int64_t created_at;         // Creation timestamp
    int64_t updated_at;         // Update timestamp

    Customer() = default;
    Customer(const std::string &n, const std::string &ph = "", const std::string &em = "")
        : name(n), phone(ph), email(em) {
        // Set default timestamps
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        created_at = static_cast<int64_t>(time_t);
        updated_at = created_at;
    }
};

// Order data structure (matches order_service.proto)
struct Order
{
    int64_t id;                    // Auto-increment primary key
    std::string name;              // Order name
    std::string description;       // Order description
    std::string attachments;       // JSON string of attachments array
    int32_t print_quantity;        // Print quantity
    int64_t customer_id;           // Associated customer ID (int64_t)
    int64_t created_at;            // Creation timestamp
    int64_t updated_at;            // Update timestamp

    Order() = default;
    Order(const std::string &name, const std::string &desc = "", int64_t customer_id = 0, int32_t quantity = 1)
        : name(name), description(desc), customer_id(customer_id), print_quantity(quantity) {
        // Set default timestamps
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        created_at = static_cast<int64_t>(time_t);
        updated_at = created_at;
    }
};

// EmbedDevice data structure (matches embed_device_service.proto Device message)
struct EmbedDevice
{
    int64_t device_id;             // Auto-increment primary key (database internal)
    std::string device_name;       // Device name
    int device_type;               // Device type (DeviceType enum value)
    
    // Hardware information
    std::string model;             // Device model
    std::string serial_number;     // Serial number
    std::string firmware_version;  // Firmware version
    std::string hardware_version;  // Hardware version
    std::string manufacturer;      // Manufacturer
    
    // Network information
    std::string ip_address;        // IP address
    int32_t port;                  // Port number
    std::string mac_address;       // MAC address
    
    // Status information
    int status;                    // Current device status (DeviceStatus enum value)
    
    // Location and description
    std::string location;          // Physical location
    std::string description;       // Device description
    
    // Timestamps
    int64_t last_seen;             // Last seen timestamp (Unix time in seconds)
    int64_t created_at;            // Creation timestamp
    int64_t updated_at;            // Last update timestamp
    
    // Session information
    std::string session_id;        // Current session ID (if connected)
    
    // Extended attributes (stored as JSON strings)
    std::string capabilities;      // Device capabilities (JSON string of key-value pairs)
    std::string metadata;          // Additional metadata (JSON string of key-value pairs)

    EmbedDevice() = default;
    EmbedDevice(const std::string &device_name, int device_type = 0,
                const std::string &model = "", const std::string &serial_number = "",
                const std::string &firmware_version = "", const std::string &hardware_version = "",
                const std::string &manufacturer = "", const std::string &ip_address = "",
                int32_t port = 0, const std::string &mac_address = "", int status = 0,
                const std::string &location = "", const std::string &description = "",
                const std::string &capabilities = "", const std::string &metadata = "")
        : device_name(device_name), device_type(device_type), model(model),
          serial_number(serial_number), firmware_version(firmware_version),
          hardware_version(hardware_version), manufacturer(manufacturer),
          ip_address(ip_address), port(port), mac_address(mac_address),
          status(status), location(location), description(description),
          capabilities(capabilities), metadata(metadata) {
        // Set default timestamps
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        created_at = static_cast<int64_t>(time_t);
        updated_at = created_at;
        last_seen = created_at;
    }
};

// Print task data structure
struct PrintTask
{
    int id;
    int order_id;
    std::string print_name;
    std::string gcode_filename;
    int total_quantity;
    int completed_quantity;

    PrintTask() = default;
    PrintTask(int oid, const std::string &name, const std::string &gcode, int total)
        : order_id(oid), print_name(name), gcode_filename(gcode),
          total_quantity(total), completed_quantity(0) {}
};

// gcode 文件 
struct Gcode_file
{
  int id;
  std::string filename;
  std::string encrypted_path;
  std::string aeskey; // 存储32字节的AES密钥
  std::string upload_time;
};


namespace lmdb
{
    struct lmDBCoreImpl;
    class LM_DB_API lmDBCore
    {
    public:
        lmDBCore(const std::string &db_name);
        ~lmDBCore();

        // Initialize database with all tables
        DB_RESULT initialize();

        // User operations (matches user_service.proto)
        DB_RESULT add_user(const std::string &name, const std::string &email, const std::string &password,
                          const std::string &phone = "", const std::string &address = "", int role = 1);
        DB_RESULT add_user(User &user);  // 新增：传入User结构体的接口
        DB_RESULT remove_user(int64_t id);
        DB_RESULT remove_user(const std::string &name);
        DB_RESULT update_user(int64_t id, const std::string &name, const std::string &email,
                         const std::string &phone = "", const std::string &address = "", int role = -1);
        DB_RESULT update_user(const std::string &name, const std::string &new_name, const std::string &email,
                         const std::string &phone = "", const std::string &address = "", int role = -1);
        DB_RESULT update_user(const User &user);  // 新增：传入User结构体的更新接口
        DB_RESULT set_password(int64_t id, const std::string &new_password);
        DB_RESULT set_password(const std::string &name, const std::string &new_password);
        DB_RESULT get_password(int64_t id, std::string &out_password);
        DB_RESULT get_user_by_id(int64_t id, User &out_user);
        DB_RESULT get_user_by_name(const std::string &name, User &out_user);
        DB_RESULT get_all_users(std::vector<User> &out_users);
        DB_RESULT verify_user(const std::string &name, const std::string &password);


        // Customer operations
        DB_RESULT add_customer(const std::string &name, const std::string &phone, const std::string &email = "",
                          const std::string &avatar_image = "", const std::string &address = "", const std::string &company = "",
                          const std::string &position = "", const std::string &notes = "");
        DB_RESULT add_customer(Customer &customer);  // 新增：传入Customer结构体的接口
        DB_RESULT remove_customer(int64_t customer_id);
        DB_RESULT remove_customer(const std::string &name);
        DB_RESULT update_customer(int64_t customer_id, const std::string &name, const std::string &phone,
                             const std::string &email = "", const std::string &avatar_image = "", const std::string &address = "",
                             const std::string &company = "", const std::string &position = "", const std::string &notes = "");
        DB_RESULT update_customer(const std::string &name, const std::string &new_name, const std::string &phone,
                             const std::string &email = "", const std::string &avatar_image = "", const std::string &address = "",
                             const std::string &company = "", const std::string &position = "", const std::string &notes = "");
        DB_RESULT update_customer(const Customer &customer);  // 新增：传入Customer结构体的更新接口
        DB_RESULT get_all_customers(std::vector<Customer> &out_customers);
        DB_RESULT get_customer_by_id(int64_t customer_id, Customer &out_customer);
        DB_RESULT get_customer_by_name(const std::string &name, Customer &out_customer);


        // Order operations
        DB_RESULT add_order(const std::string &name, const std::string &description, int64_t customer_id,
                       int32_t print_quantity = 1, const std::string &attachments = "");
        DB_RESULT add_order(Order &order);  // 新增：传入Order结构体的接口
        DB_RESULT remove_order(int64_t order_id);
        DB_RESULT remove_order(const std::string &name);
        DB_RESULT update_order(int64_t order_id, const std::string &name, const std::string &description,
                          int64_t customer_id, int32_t print_quantity, const std::string &attachments);
        DB_RESULT update_order(const std::string &name, const std::string &new_name, const std::string &description,
                          int64_t customer_id, int32_t print_quantity, const std::string &attachments);
        DB_RESULT update_order(const Order &order);  // 新增：传入Order结构体的更新接口
        DB_RESULT get_all_orders(std::vector<Order> &out_orders);
        DB_RESULT get_order_by_id(int64_t order_id, Order &out_order);
        DB_RESULT get_orders_by_customer(int64_t customer_id, std::vector<Order> &out_orders);


        // EmbedDevice operations
        DB_RESULT add_embed_device(const std::string &device_name, int device_type = 0,
                              const std::string &model = "", const std::string &serial_number = "",
                              const std::string &firmware_version = "", const std::string &hardware_version = "",
                              const std::string &manufacturer = "", const std::string &ip_address = "",
                              int32_t port = 0, const std::string &mac_address = "", int status = 0,
                              const std::string &location = "", const std::string &description = "",
                              const std::string &capabilities = "", const std::string &metadata = "");
        DB_RESULT add_embed_device(EmbedDevice &device);  // 新增：传入EmbedDevice结构体的接口
        DB_RESULT remove_embed_device(int64_t device_id);
        DB_RESULT remove_embed_device(const std::string &device_name);
        DB_RESULT update_embed_device(int64_t device_id, const std::string &device_name, int device_type = -1,
                                 const std::string &model = "", const std::string &serial_number = "",
                                 const std::string &firmware_version = "", const std::string &hardware_version = "",
                                 const std::string &manufacturer = "", const std::string &ip_address = "",
                                 int32_t port = -1, const std::string &mac_address = "", int status = -1,
                                 const std::string &location = "", const std::string &description = "",
                                 const std::string &capabilities = "", const std::string &metadata = "");
        DB_RESULT update_embed_device(const std::string &device_name, const std::string &new_device_name, int device_type = -1,
                                 const std::string &model = "", const std::string &serial_number = "",
                                 const std::string &firmware_version = "", const std::string &hardware_version = "",
                                 const std::string &manufacturer = "", const std::string &ip_address = "",
                                 int32_t port = -1, const std::string &mac_address = "", int status = -1,
                                 const std::string &location = "", const std::string &description = "",
                                 const std::string &capabilities = "", const std::string &metadata = "");
        DB_RESULT update_embed_device(const EmbedDevice &device);  // 新增：传入EmbedDevice结构体的更新接口
        DB_RESULT get_all_embed_devices(std::vector<EmbedDevice> &out_devices);
        DB_RESULT get_embed_device_by_id(int64_t device_id, EmbedDevice &out_device);
        DB_RESULT get_embed_device_by_name(const std::string &device_name, EmbedDevice &out_device);
        DB_RESULT get_embed_devices_by_type(int device_type, std::vector<EmbedDevice> &out_devices);


        // Print task operations
        DB_RESULT add_print_task(int order_id, const std::string &print_name, const std::string &gcode_filename, int total_quantity);
        DB_RESULT add_print_task(PrintTask &task);  // 新增：传入PrintTask结构体的接口
        DB_RESULT remove_print_task(int print_task_id);
        DB_RESULT remove_print_task(const std::string &print_name);
        DB_RESULT update_print_task(int print_task_id, const std::string &print_name, const std::string &gcode_filename,
                               int total_quantity, int completed_quantity);
        DB_RESULT update_print_task(const std::string &print_name, const std::string &new_print_name, const std::string &gcode_filename,
                               int total_quantity, int completed_quantity);
        DB_RESULT update_print_task(const PrintTask &task);  // 新增：传入PrintTask结构体的更新接口
        DB_RESULT get_all_print_tasks(std::vector<PrintTask> &out_tasks);
        DB_RESULT get_print_task_by_id(int print_task_id, PrintTask &out_task);
        DB_RESULT get_print_tasks_by_order(int order_id, std::vector<PrintTask> &out_tasks);
        DB_RESULT update_print_progress(int print_task_id, int completed_quantity);


        // G-code file operations
        DB_RESULT add_gcode_file(const std::string& filename, const std::string& encrypted_path, const std::string& aeskey);
        DB_RESULT add_gcode_file(Gcode_file &file);  // 新增：传入Gcode_file结构体的接口
        DB_RESULT remove_gcode_file(int gcode_file_id);
        DB_RESULT remove_gcode_file(const std::string& filename);
        DB_RESULT update_gcode_file(int gcode_file_id, const std::string& filename, const std::string& encrypted_path, const std::string& aeskey);
        DB_RESULT update_gcode_file(const std::string& filename, const std::string& new_filename, const std::string& encrypted_path, const std::string& aeskey);
        DB_RESULT update_gcode_file(const Gcode_file &file);  // 新增：传入Gcode_file结构体的更新接口
        DB_RESULT get_all_gcode_files(std::vector<Gcode_file> &out_files);
        DB_RESULT get_gcode_file_by_id(int gcode_file_id, Gcode_file &out_file);
        DB_RESULT get_gcode_file_by_filename(const std::string& filename, Gcode_file &out_file);
        DB_RESULT get_total_gcode_files_count(int &out_count);


        // Statistics
        DB_RESULT get_total_orders_count(int &out_count);
        DB_RESULT get_total_print_tasks_count(int &out_count);
        DB_RESULT get_completed_print_tasks_count(int &out_count);

        // Database maintenance
        void clear_all_data();
        void print_database_status();
        void print(const std::string &query = "");

        const std::string& get_database_path() const;
        
        // Database backup and restore
        DB_RESULT backup_database(const std::string& backup_path);
        DB_RESULT restore_database(const std::string& backup_path);
        DB_RESULT export_to_sql(const std::string& sql_file_path);
        DB_RESULT import_from_sql(const std::string& sql_file_path);

        
        // Test functions
        void populate_test_data();
        
        // G-code encryption/decryption test functions
        void test_gcode_encryption_decryption();
        
        // Generate comprehensive test cases for all database functions
        void generate_database_test_cases();

        // Static utility functions
        static std::vector<std::string> enumerate_database_files(const std::string& data_directory = "");
        static std::string get_default_data_directory();

    protected:
        lmDBCoreImpl *impl;
        std::string db_path_;
    };
}
