#pragma once
#include "lm/export.h"
#include <string>
#include <vector>
#include <ctime>
#include <chrono>

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
    std::string customer_id;       // Associated customer ID (string)
    int64_t created_at;            // Creation timestamp
    int64_t updated_at;            // Update timestamp

    Order() = default;
    Order(const std::string &name, const std::string &desc = "", const std::string &customer_id = "", int32_t quantity = 1)
        : name(name), description(desc), customer_id(customer_id), print_quantity(quantity) {
        // Set default timestamps
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        created_at = static_cast<int64_t>(time_t);
        updated_at = created_at;
    }
};

// EmbedDevice data structure (matches embeddevice::DeviceInfo)
struct EmbedDevice
{
    int64_t id;                    // Auto-increment primary key
    std::string device_name;       // Device name
    std::string device_type;       // Device type
    std::string firmware_version;  // Firmware version
    std::string hardware_version;  // Hardware version
    std::string manufacturer;      // Manufacturer
    std::string capabilities;      // JSON string of capabilities map
    int64_t created_at;            // Creation timestamp
    int64_t updated_at;            // Update timestamp

    EmbedDevice() = default;
    EmbedDevice(const std::string &name, const std::string &type, const std::string &manufacturer = "")
        : device_name(name), device_type(type), manufacturer(manufacturer) {
        // Set default timestamps
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        created_at = static_cast<int64_t>(time_t);
        updated_at = created_at;
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
        lmDBCore(const std::string &db_path);
        ~lmDBCore();

        // Initialize database with all tables
        bool initialize();

        // User operations (matches user_service.proto)
        bool add_user(const std::string &name, const std::string &email,
                      const std::string &phone = "", const std::string &address = "", int role = 1);
        bool remove_user(int64_t id);
        bool update_user(int64_t id, const std::string &name, const std::string &email,
                         const std::string &phone = "", const std::string &address = "", int role = -1);
        bool set_password(int64_t id, const std::string &new_password);
        bool set_password(const std::string &name, const std::string &new_password);
        bool get_password(int64_t id, std::string &out_password);
        User get_user_by_id(int64_t id);
        User get_user_by_name(const std::string &name);
        std::vector<User> get_all_users();
        bool verify_user(const std::string &name, const std::string &password);

        // Customer operations
        bool add_customer(const std::string &name, const std::string &phone, const std::string &email = "",
                          const std::string &avatar_image = "", const std::string &address = "", const std::string &company = "",
                          const std::string &position = "", const std::string &notes = "");
        bool remove_customer(int64_t customer_id);
        bool update_customer(int64_t customer_id, const std::string &name, const std::string &phone,
                             const std::string &email = "", const std::string &avatar_image = "", const std::string &address = "",
                             const std::string &company = "", const std::string &position = "", const std::string &notes = "");
        std::vector<Customer> get_all_customers();
        Customer get_customer_by_id(int64_t customer_id);
        Customer get_customer_by_name(const std::string &name);

        // Order operations
        bool add_order(const std::string &name, const std::string &description, const std::string &customer_id,
                       int32_t print_quantity = 1, const std::string &attachments = "");
        bool remove_order(int64_t order_id);
        bool update_order(int64_t order_id, const std::string &name, const std::string &description,
                          const std::string &customer_id, int32_t print_quantity, const std::string &attachments);
        std::vector<Order> get_all_orders();
        Order get_order_by_id(int64_t order_id);
        std::vector<Order> get_orders_by_customer(const std::string &customer_id);

        // EmbedDevice operations
        bool add_embed_device(const std::string &device_name, const std::string &device_type,
                              const std::string &firmware_version = "", const std::string &hardware_version = "",
                              const std::string &manufacturer = "", const std::string &capabilities = "");
        bool remove_embed_device(int64_t device_id);
        bool update_embed_device(int64_t device_id, const std::string &device_name, const std::string &device_type,
                                 const std::string &firmware_version, const std::string &hardware_version,
                                 const std::string &manufacturer, const std::string &capabilities);
        std::vector<EmbedDevice> get_all_embed_devices();
        EmbedDevice get_embed_device_by_id(int64_t device_id);
        EmbedDevice get_embed_device_by_name(const std::string &device_name);
        std::vector<EmbedDevice> get_embed_devices_by_type(const std::string &device_type);

        // Print task operations
        bool add_print_task(int order_id, const std::string &print_name, const std::string &gcode_filename, int total_quantity);
        bool remove_print_task(int print_task_id);
        bool update_print_task(int print_task_id, const std::string &print_name, const std::string &gcode_filename,
                               int total_quantity, int completed_quantity);
        std::vector<PrintTask> get_all_print_tasks();
        PrintTask get_print_task_by_id(int print_task_id);
        std::vector<PrintTask> get_print_tasks_by_order(int order_id);
        bool update_print_progress(int print_task_id, int completed_quantity);

        // G-code file operations
        bool add_gcode_file(const std::string& filename, const std::string& encrypted_path, const std::string& aeskey);
        bool remove_gcode_file(int gcode_file_id);
        bool update_gcode_file(int gcode_file_id, const std::string& filename, const std::string& encrypted_path, const std::string& aeskey);
        std::vector<Gcode_file> get_all_gcode_files();
        Gcode_file get_gcode_file_by_id(int gcode_file_id);
        Gcode_file get_gcode_file_by_filename(const std::string& filename);
        int get_total_gcode_files_count();

        // Statistics
        int get_total_orders_count();
        int get_total_print_tasks_count();
        int get_completed_print_tasks_count();

        // Database maintenance
        void clear_all_data();
        void print_database_status();
        void print(const std::string &query = "");

    protected:
        lmDBCoreImpl *impl;
    };
}
