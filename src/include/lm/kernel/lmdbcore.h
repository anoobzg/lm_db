#pragma once
#include "lm/export.h"
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <memory>


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
    std::string serial_number;     // Order serial number (unique identifier)
    std::string description;       // Order description
    std::string attachments;       // JSON string of attachments array
    int32_t print_quantity;        // Print quantity
    std::string customer_name;     // Associated customer name
    int64_t created_at;            // Creation timestamp
    int64_t updated_at;            // Update timestamp

    Order() = default;
    Order(const std::string &name, const std::string &desc = "", const std::string &customer_name = "", int32_t quantity = 1)
        : name(name), description(desc), customer_name(customer_name), print_quantity(quantity) {
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
    EmbedDevice(const std::string &serial_number, const std::string &device_name = "", int device_type = 0,
                const std::string &model = "", const std::string &firmware_version = "", const std::string &hardware_version = "",
                const std::string &manufacturer = "", const std::string &ip_address = "",
                int32_t port = 0, const std::string &mac_address = "", int status = 0,
                const std::string &location = "", const std::string &description = "",
                const std::string &capabilities = "", const std::string &metadata = "")
        : serial_number(serial_number), device_name(device_name), device_type(device_type), model(model),
          firmware_version(firmware_version), hardware_version(hardware_version), manufacturer(manufacturer),
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
  int64_t id;
  std::string order_serial_number;  // Corresponds to Order's serial_number
  std::string print_name;
  std::string file_uuid;
  int total_quantity;
  int completed_quantity;

    PrintTask() = default;
    PrintTask(const std::string &order_serial, const std::string &name, const std::string &file_uuid, int total)
        : order_serial_number(order_serial), print_name(name), file_uuid(file_uuid),
          total_quantity(total), completed_quantity(0) {}
};

// 
struct File_record
{
  int id;
  std::string uuid;              // 
  std::string filename;          // 
  std::string aeskey;            //  
  std::string upload_time;       //  
  std::string file_type;         // (gcode, stl, etc.)
  std::string customer_name;     // Customer name instead of customer_id
};

// Order File_record mapping
struct OrderFile
{
  int id;                        //  main key
  int order_id;                  //  order id 
  std::string file_uuid;         //  file uuid 
  std::string created_at;        //  create time
  std::string description;       //  
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
        DB_RESULT update_user(const User &user);  //  
        DB_RESULT update_user_role_by_name(const std::string &name, int role);  //  
        DB_RESULT set_password(int64_t id, const std::string &new_password);
        DB_RESULT set_password(const std::string &name, const std::string &new_password);
        DB_RESULT get_password(int64_t id, std::string &out_password);
        DB_RESULT get_user_by_id(int64_t id, User &out_user);
        DB_RESULT get_user_by_name(const std::string &name, User &out_user);
        DB_RESULT get_all_users(std::vector<User> &out_users);
        DB_RESULT verify_user(const std::string &name, const std::string &password);
        
        // User role validation helper functions
        bool is_valid_user_role(int role);  //  
 
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
        DB_RESULT add_order(const std::string &name, const std::string &description, const std::string &customer_name,
                       int32_t print_quantity, const std::string &attachments, std::string &out_serial_number);
        DB_RESULT add_order(Order &order, std::string &out_serial_number);  // 新增：传入Order结构体的接口，返回序列号
        DB_RESULT remove_order(int64_t order_id);
        DB_RESULT remove_order(const std::string &serial_number);
        DB_RESULT update_order(int64_t order_id, const std::string &name, const std::string &description,
        const std::string &customer_name, int32_t print_quantity, const std::string &attachments);
        DB_RESULT update_order(const std::string &serial_number, const std::string &name, const std::string &description,
                          const std::string &customer_name, int32_t print_quantity, const std::string &attachments);
        DB_RESULT update_order(const Order &order);  // 新增：传入Order结构体的更新接口
        DB_RESULT get_all_orders(std::vector<Order> &out_orders);
		DB_RESULT get_order_by_id(int64_t order_id, Order &out_order);
        DB_RESULT get_order_by_serial(const std::string &serial_number, Order &out_order);
        DB_RESULT get_orders_by_customer(const std::string &customer_name, std::vector<Order> &out_orders);


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
        DB_RESULT remove_embed_device_by_serial_number(const std::string &serial_number);
        DB_RESULT update_embed_device(int64_t device_id, const std::string &device_name, int device_type = -1,
                                 const std::string &model = "", const std::string &serial_number = "",
                                 const std::string &firmware_version = "", const std::string &hardware_version = "",
                                 const std::string &manufacturer = "", const std::string &ip_address = "",
                                 int32_t port = -1, const std::string &mac_address = "", int status = -1,
                                 const std::string &location = "", const std::string &description = "",
                                 const std::string &capabilities = "", const std::string &metadata = "");

        DB_RESULT update_embed_device(const std::string &serial_number, const std::string &new_device_name, int device_type = -1,
                                 const std::string &model = "", const std::string &new_serial_number = "",
                                 const std::string &firmware_version = "", const std::string &hardware_version = "",
                                 const std::string &manufacturer = "", const std::string &ip_address = "",
                                 int32_t port = -1, const std::string &mac_address = "", int status = -1,
                                 const std::string &location = "", const std::string &description = "",
                                 const std::string &capabilities = "", const std::string &metadata = "");

        DB_RESULT update_embed_device(const EmbedDevice &device);  // 新增：传入EmbedDevice结构体的更新接口
        DB_RESULT get_all_embed_devices(std::vector<EmbedDevice> &out_devices);
        DB_RESULT get_embed_device_by_id(int64_t device_id, EmbedDevice &out_device);
        DB_RESULT get_embed_device_by_serial_number(const std::string &serial_number, EmbedDevice &out_device);
        DB_RESULT get_embed_devices_by_type(int device_type, std::vector<EmbedDevice> &out_devices);


        // Print task operations
        DB_RESULT add_print_task(const std::string &order_serial_number, const std::string &print_name, const std::string &file_uuid, int total_quantity);
        DB_RESULT add_print_task(PrintTask &task);  // 新增：传入PrintTask结构体的接口
        DB_RESULT remove_print_task(int64_t print_task_id);
        DB_RESULT remove_print_task(const std::string &print_name);
        DB_RESULT update_print_task(int64_t print_task_id, const std::string &print_name, const std::string &file_uuid,
                               int total_quantity, int completed_quantity);
        DB_RESULT update_print_task(const std::string &print_name, const std::string &new_print_name, const std::string &file_uuid,
                               int total_quantity, int completed_quantity);
        DB_RESULT update_print_task(const PrintTask &task);  //
        DB_RESULT get_all_print_tasks(std::vector<PrintTask> &out_tasks);
        DB_RESULT get_print_task_by_id(int64_t print_task_id, PrintTask &out_task);
        DB_RESULT get_print_tasks_by_order(const std::string &order_serial_number, std::vector<PrintTask> &out_tasks);
        DB_RESULT update_print_progress(int64_t print_task_id, int completed_quantity);


        // File record operations
        DB_RESULT add_file_record(const std::string& filename, const std::string& aeskey, const std::string& customer_name, const std::string& file_type = "gcode");
        DB_RESULT add_file_record(File_record &file);  //
        DB_RESULT remove_file_record(const std::string& uuid);
        DB_RESULT update_file_record(const std::string& uuid, const std::string& filename, const std::string& aeskey, const std::string& customer_name, const std::string& file_type = "gcode");
        DB_RESULT update_file_record(File_record &file);  // 
        DB_RESULT set_file_aeskey_by_uuid(const std::string& uuid, const std::string& aeskey);  //
        DB_RESULT get_all_file_records(std::vector<File_record> &out_files);
        DB_RESULT get_file_records_by_customer(const std::string& customer_name, std::vector<File_record> &out_files);  //
        DB_RESULT get_file_record(const std::string& uuid, File_record &out_file);
        DB_RESULT get_total_file_records_count(int &out_count);
        DB_RESULT get_file_records_count_by_customer(const std::string& customer_name, int &out_count);  //

        // Order-File relationship operations 
        DB_RESULT add_order_file_relation(int order_id, const std::string& file_uuid, const std::string& description = "");
        DB_RESULT remove_order_file_relation(int order_id, const std::string& file_uuid);
        DB_RESULT remove_all_order_file_relations(int order_id);  //  
        DB_RESULT remove_all_file_order_relations(const std::string& file_uuid);  //  
        DB_RESULT get_files_by_order(int order_id, std::vector<File_record> &out_files);  // 
        DB_RESULT get_orders_by_file(const std::string& file_uuid, std::vector<Order> &out_orders);  // 
        DB_RESULT get_order_file_relations(int order_id, std::vector<OrderFile> &out_relations);  //  
        DB_RESULT get_file_order_relations(const std::string& file_uuid, std::vector<OrderFile> &out_relations);  // 
        DB_RESULT update_order_file_relation(int order_id, const std::string& file_uuid, const std::string& description);  //  
        DB_RESULT get_order_file_relation_count(int order_id, int &out_count);  //  
        DB_RESULT get_file_order_relation_count(const std::string& file_uuid, int &out_count);  //  

        // File encryption and decryption operations (static functions)
  
        DB_RESULT encrypt_file_with_key(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key, const std::string& file_uuid,int chunk_index = 0, bool append_mode = false);
        DB_RESULT decrypt_file_with_key(const std::string& file_uuid, const std::vector<uint8_t>& key, std::vector<uint8_t>& output_data);
        DB_RESULT decrypt_file_chunk(const std::string& file_uuid, const std::vector<uint8_t>& key, int chunk_index, std::vector<uint8_t>& output_data);  // 新增：解密指定块
        DB_RESULT generate_random_aes_key(std::vector<uint8_t>& out_key);
        DB_RESULT generate_uuid(std::string& out_uuid);

        // Statistics
        DB_RESULT get_total_orders_count(int &out_count);
        DB_RESULT get_total_print_tasks_count(int &out_count);
        DB_RESULT get_completed_print_tasks_count(int &out_count);

        // Database maintenance
        void clear_all_data();
        void print_database_status();
        void print(const std::string &query = "");

        const std::string& get_database_path() const;
        const std::string& get_file_dir() const; 
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
        std::string file_dir_;  
    };
}
