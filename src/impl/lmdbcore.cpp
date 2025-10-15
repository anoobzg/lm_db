#include "lm/kernel/lmdbcore.h"

#include "sqlite.hpp"
#include "dbng.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>

// Register ORM mappings
REGISTER_AUTO_KEY(User, id)
YLT_REFL(User, id, name, email, phone, address, password, role, permissions, groups, created_at, updated_at)

REGISTER_AUTO_KEY(Customer, id)
YLT_REFL(Customer, id, name, phone, email, avatar_image, address, company, position, notes, created_at, updated_at)

REGISTER_AUTO_KEY(Order, id)
YLT_REFL(Order, id, name, description, attachments, print_quantity, customer_id, created_at, updated_at)

REGISTER_AUTO_KEY(EmbedDevice, id)
YLT_REFL(EmbedDevice, id, device_name, device_type, firmware_version, hardware_version, manufacturer, capabilities, created_at, updated_at)

REGISTER_AUTO_KEY(PrintTask, id)
YLT_REFL(PrintTask, id, order_id, print_name, gcode_filename, total_quantity, completed_quantity)

REGISTER_AUTO_KEY(Gcode_file, id)
YLT_REFL(Gcode_file, id, filename, encrypted_path, aeskey, upload_time)

namespace lmdb {
    struct lmDBCoreImpl
    {
        ormpp::dbng<ormpp::sqlite> sqlite;
    };

    lmDBCore::lmDBCore(const std::string& db_path) 
        : impl(new lmDBCoreImpl()) 
    {
        impl->sqlite.connect(db_path);
    }   

    lmDBCore::~lmDBCore() 
    { 
        delete impl; 
        impl = nullptr;
    }

    bool lmDBCore::initialize()
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
            impl->sqlite.create_datatable<User>(user_key, user_not_null);

            ormpp_auto_key customer_key{"id"};
            ormpp_not_null customer_not_null{{"name"}};
            impl->sqlite.create_datatable<Customer>(customer_key, customer_not_null);

            ormpp_auto_key order_key{"id"};
            ormpp_not_null order_not_null{{"name"}};
            impl->sqlite.create_datatable<Order>(order_key, order_not_null);

            ormpp_auto_key embed_device_key{"id"};
            ormpp_not_null embed_device_not_null{{"device_name"}};
            impl->sqlite.create_datatable<EmbedDevice>(embed_device_key, embed_device_not_null);

            ormpp_auto_key print_task_key{"id"};
            impl->sqlite.create_datatable<PrintTask>(print_task_key);

            ormpp_auto_key gcode_file_key{"id"};
            ormpp_unique gcode_file_unique{{"filename"}};
            impl->sqlite.create_datatable<Gcode_file>(gcode_file_key, gcode_file_unique);

            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Database initialization failed: " << e.what() << std::endl;
            return false;
        }
    }

    // User operations (matches user_service.proto)
    bool lmDBCore::add_user(const std::string& name, const std::string& email,
                            const std::string& phone, const std::string& address, int role)
    {
        try
        {
            auto existing = impl->sqlite.query_s<User>("name = ?", name);
            if (!existing.empty())
            {
                return false; // User name already exists
            }

            User user;
            user.name = name;
            user.email = email;
            user.phone = phone;
            user.address = address;
            user.password = "";
            user.role = role;
            user.permissions = "[]";  // Empty JSON array
            user.groups = "[]";       // Empty JSON array
            
            // Set timestamps
            time_t now = time(0);
            user.created_at = static_cast<int64_t>(now);
            user.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(user);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add user failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::remove_user(int64_t id)
    {
        try
        {
            impl->sqlite.delete_records<User>("id = " + std::to_string(id));
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove user failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::update_user(int64_t id, const std::string& name, const std::string& email,
                               const std::string& phone, const std::string& address, int role)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.empty())
            {
                return false;
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
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update user failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::set_password(int64_t id, const std::string& new_password)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.size() == 1) {
                User u = users[0];
                u.password = new_password;
                u.updated_at = static_cast<int64_t>(time(0));
                impl->sqlite.update(u);
                return true;
            }
            return false;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Set password failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::set_password(const std::string& name, const std::string& new_password)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            if (users.size() == 1) {
                User u = users[0];
                u.password = new_password;
                u.updated_at = static_cast<int64_t>(time(0));
                impl->sqlite.update(u);
                return true;
            }
            return false;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Set password failed: " << e.what() << std::endl;
            return false;
        }
    }
        
    bool lmDBCore::get_password(int64_t id, std::string& out_password)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            if (users.size() == 1) {
                out_password = users[0].password;
                return true;
            }
            return false;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get password failed: " << e.what() << std::endl;
            return false;
        }
    }

    User lmDBCore::get_user_by_id(int64_t id)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("id = ?", id);
            return users.empty() ? User() : users[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get user by id failed: " << e.what() << std::endl;
            return User();
        }
    }

    User lmDBCore::get_user_by_name(const std::string& name)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("name = ?", name);
            return users.empty() ? User() : users[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get user by name failed: " << e.what() << std::endl;
            return User();
        }
    }

    std::vector<User> lmDBCore::get_all_users()
    {
        try
        {
            return impl->sqlite.query_s<User>("");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all users failed: " << e.what() << std::endl;
            return {};
        }
    }

    bool lmDBCore::verify_user(const std::string& name, const std::string& password)
    {
        try
        {
            auto users = impl->sqlite.query_s<User>("name = ? AND password = ?", name, password);
            return !users.empty();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Verify user failed: " << e.what() << std::endl;
            return false;
        }
    }


    // Customer operations
    bool lmDBCore::add_customer(const std::string& name, const std::string& phone, const std::string& email,
                                const std::string& avatar_image, const std::string& address, const std::string& company,
                                const std::string& position, const std::string& notes)
    {
        try
        {
            auto existing = impl->sqlite.query_s<Customer>("name = ?", name);
            if (!existing.empty())
            {
                return false; // Customer name already exists
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
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add customer failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::remove_customer(int64_t customer_id)
    {
        try
        {
            impl->sqlite.delete_records<Customer>("id = " + std::to_string(customer_id));
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove customer failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::update_customer(int64_t customer_id, const std::string& name, const std::string& phone,
                                   const std::string& email, const std::string& avatar_image, const std::string& address,
                                   const std::string& company, const std::string& position, const std::string& notes)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("id = ?", customer_id);
            if (customers.empty())
            {
                return false;
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
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update customer failed: " << e.what() << std::endl;
            return false;
        }
    }

    std::vector<Customer> lmDBCore::get_all_customers()
    {
        try
        {
            return impl->sqlite.query_s<Customer>("");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all customers failed: " << e.what() << std::endl;
            return {};
        }
    }

    Customer lmDBCore::get_customer_by_id(int64_t customer_id)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("id = ?", customer_id);
            return customers.empty() ? Customer() : customers[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get customer by id failed: " << e.what() << std::endl;
            return Customer();
        }
    }

    Customer lmDBCore::get_customer_by_name(const std::string& name)
    {
        try
        {
            auto customers = impl->sqlite.query_s<Customer>("name = ?", name);
            return customers.empty() ? Customer() : customers[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get customer by name failed: " << e.what() << std::endl;
            return Customer();
        }
    }

    // Order operations
    bool lmDBCore::add_order(const std::string& name, const std::string& description, const std::string& customer_id, 
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
            
            // Set timestamps
            time_t now = time(0);
            order.created_at = static_cast<int64_t>(now);
            order.updated_at = static_cast<int64_t>(now);

            impl->sqlite.insert(order);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add order failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::remove_order(int64_t order_id)
    {
        try
        {
            impl->sqlite.delete_records<Order>("id = " + std::to_string(order_id));
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove order failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::update_order(int64_t order_id, const std::string& name, const std::string& description,
                                const std::string& customer_id, int32_t print_quantity, const std::string& attachments)
    {
        try
        {
            auto orders = impl->sqlite.query_s<Order>("id = ?", order_id);
            if (orders.empty())
            {
                return false;
            }

            Order order = orders[0];
            order.name = name;
            order.description = description;
            order.customer_id = customer_id;
            order.print_quantity = print_quantity;
            order.attachments = attachments;
            order.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(order);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update order failed: " << e.what() << std::endl;
            return false;
        }
    }

    std::vector<Order> lmDBCore::get_all_orders()
    {
        try
        {
            return impl->sqlite.query_s<Order>("");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all orders failed: " << e.what() << std::endl;
            return {};
        }
    }

    Order lmDBCore::get_order_by_id(int64_t order_id)
    {
        try
        {
            auto orders = impl->sqlite.query_s<Order>("id = ?", order_id);
            return orders.empty() ? Order() : orders[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get order by id failed: " << e.what() << std::endl;
            return Order();
        }
    }

    std::vector<Order> lmDBCore::get_orders_by_customer(const std::string& customer_id)
    {
        try
        {
            return impl->sqlite.query_s<Order>("customer_id = ?", customer_id);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get orders by customer failed: " << e.what() << std::endl;
            return {};
        }
    }

    // EmbedDevice operations
    bool lmDBCore::add_embed_device(const std::string& device_name, const std::string& device_type,
                                    const std::string& firmware_version, const std::string& hardware_version,
                                    const std::string& manufacturer, const std::string& capabilities)
    {
        try
        {
            auto existing = impl->sqlite.query_s<EmbedDevice>("device_name = ?", device_name);
            if (!existing.empty())
            {
                return false; // Device name already exists
            }

            EmbedDevice device;
            device.device_name = device_name;
            device.device_type = device_type;
            device.firmware_version = firmware_version;
            device.hardware_version = hardware_version;
            device.manufacturer = manufacturer;
            device.capabilities = capabilities;
            
            // Set timestamps
            time_t now = time(0);
            device.created_at = static_cast<int64_t>(now);
            device.updated_at = static_cast<int64_t>(now);
            
            impl->sqlite.insert(device);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add embed device failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::remove_embed_device(int64_t device_id)
    {
        try
        {
            impl->sqlite.delete_records<EmbedDevice>("id = " + std::to_string(device_id));
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove embed device failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::update_embed_device(int64_t device_id, const std::string& device_name, const std::string& device_type,
                                       const std::string& firmware_version, const std::string& hardware_version,
                                       const std::string& manufacturer, const std::string& capabilities)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("id = ?", device_id);
            if (devices.empty())
            {
                return false;
            }

            EmbedDevice device = devices[0];
            device.device_name = device_name;
            device.device_type = device_type;
            device.firmware_version = firmware_version;
            device.hardware_version = hardware_version;
            device.manufacturer = manufacturer;
            device.capabilities = capabilities;
            device.updated_at = static_cast<int64_t>(time(0));

            impl->sqlite.update(device);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update embed device failed: " << e.what() << std::endl;
            return false;
        }
    }

    std::vector<EmbedDevice> lmDBCore::get_all_embed_devices()
    {
        try
        {
            return impl->sqlite.query_s<EmbedDevice>("");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all embed devices failed: " << e.what() << std::endl;
            return {};
        }
    }

    EmbedDevice lmDBCore::get_embed_device_by_id(int64_t device_id)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("id = ?", device_id);
            return devices.empty() ? EmbedDevice() : devices[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get embed device by id failed: " << e.what() << std::endl;
            return EmbedDevice();
        }
    }

    EmbedDevice lmDBCore::get_embed_device_by_name(const std::string& device_name)
    {
        try
        {
            auto devices = impl->sqlite.query_s<EmbedDevice>("device_name = ?", device_name);
            return devices.empty() ? EmbedDevice() : devices[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get embed device by name failed: " << e.what() << std::endl;
            return EmbedDevice();
        }
    }

    std::vector<EmbedDevice> lmDBCore::get_embed_devices_by_type(const std::string& device_type)
    {
        try
        {
            return impl->sqlite.query_s<EmbedDevice>("device_type = ?", device_type);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get embed devices by type failed: " << e.what() << std::endl;
            return {};
        }
    }

    // Print task operations
    bool lmDBCore::add_print_task(int order_id, const std::string& print_name, const std::string& gcode_filename, int total_quantity)
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
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add print task failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::remove_print_task(int print_task_id)
    {
        try
        {
            impl->sqlite.delete_records<PrintTask>("id = " + std::to_string(print_task_id));
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove print task failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::update_print_task(int print_task_id, const std::string& print_name, const std::string& gcode_filename,
                                     int total_quantity, int completed_quantity)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("id = ?", print_task_id);
            if (print_tasks.empty())
            {
                return false;
            }

            PrintTask print_task = print_tasks[0];
            print_task.print_name = print_name;
            print_task.gcode_filename = gcode_filename;
            print_task.total_quantity = total_quantity;
            print_task.completed_quantity = completed_quantity;

            impl->sqlite.update(print_task);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update print task failed: " << e.what() << std::endl;
            return false;
        }
    }

    std::vector<PrintTask> lmDBCore::get_all_print_tasks()
    {
        try
        {
            return impl->sqlite.query_s<PrintTask>("");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all print tasks failed: " << e.what() << std::endl;
            return {};
        }
    }

    PrintTask lmDBCore::get_print_task_by_id(int print_task_id)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("id = ?", print_task_id);
            return print_tasks.empty() ? PrintTask() : print_tasks[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get print task by id failed: " << e.what() << std::endl;
            return PrintTask();
        }
    }

    std::vector<PrintTask> lmDBCore::get_print_tasks_by_order(int order_id)
    {
        try
        {
            return impl->sqlite.query_s<PrintTask>("order_id = ?", order_id);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get print tasks by order failed: " << e.what() << std::endl;
            return {};
        }
    }

    bool lmDBCore::update_print_progress(int print_task_id, int completed_quantity)
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("id = ?", print_task_id);
            if (print_tasks.empty())
            {
                return false;
            }

            PrintTask print_task = print_tasks[0];
            print_task.completed_quantity = completed_quantity;

            impl->sqlite.update(print_task);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update print progress failed: " << e.what() << std::endl;
            return false;
        }
    }

    // G-code file operations
    bool lmDBCore::add_gcode_file(const std::string& filename, const std::string& encrypted_path, const std::string& aeskey)
    {
        try
        {
            auto existing = impl->sqlite.query_s<Gcode_file>("filename = ?", filename);
            if (!existing.empty())
            {
                return false; // Filename already exists
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
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Add gcode file failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::remove_gcode_file(int gcode_file_id)
    {
        try
        {
            impl->sqlite.delete_records<Gcode_file>("id = " + std::to_string(gcode_file_id));
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Remove gcode file failed: " << e.what() << std::endl;
            return false;
        }
    }

    bool lmDBCore::update_gcode_file(int gcode_file_id, const std::string& filename, const std::string& encrypted_path, const std::string& aeskey)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("id = ?", gcode_file_id);
            if (gcode_files.empty())
            {
                return false;
            }

            Gcode_file gcode_file = gcode_files[0];
            gcode_file.filename = filename;
            gcode_file.encrypted_path = encrypted_path;
            
            // Copy AES key
            gcode_file.aeskey = std::string(aeskey, 32);

            impl->sqlite.update(gcode_file);
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Update gcode file failed: " << e.what() << std::endl;
            return false;
        }
    }

    std::vector<Gcode_file> lmDBCore::get_all_gcode_files()
    {
        try
        {
            return impl->sqlite.query_s<Gcode_file>("");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get all gcode files failed: " << e.what() << std::endl;
            return {};
        }
    }

    Gcode_file lmDBCore::get_gcode_file_by_id(int gcode_file_id)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("id = ?", gcode_file_id);
            return gcode_files.empty() ? Gcode_file() : gcode_files[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get gcode file by id failed: " << e.what() << std::endl;
            return Gcode_file();
        }
    }

    Gcode_file lmDBCore::get_gcode_file_by_filename(const std::string& filename)
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("filename = ?", filename);
            return gcode_files.empty() ? Gcode_file() : gcode_files[0];
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get gcode file by filename failed: " << e.what() << std::endl;
            return Gcode_file();
        }
    }

    int lmDBCore::get_total_gcode_files_count()
    {
        try
        {
            auto gcode_files = impl->sqlite.query_s<Gcode_file>("");
            return static_cast<int>(gcode_files.size());
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total gcode files count failed: " << e.what() << std::endl;
            return 0;
        }
    }

    // Statistics
    int lmDBCore::get_total_orders_count()
    {
        try
        {
            auto orders = impl->sqlite.query_s<Order>("");
            return static_cast<int>(orders.size());
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total orders count failed: " << e.what() << std::endl;
            return 0;
        }
    }

    int lmDBCore::get_total_print_tasks_count()
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("");
            return static_cast<int>(print_tasks.size());
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get total print tasks count failed: " << e.what() << std::endl;
            return 0;
        }
    }

    int lmDBCore::get_completed_print_tasks_count()
    {
        try
        {
            auto print_tasks = impl->sqlite.query_s<PrintTask>("completed_quantity >= total_quantity");
            return static_cast<int>(print_tasks.size());
        }
        catch (const std::exception &e)
        {
            std::cerr << "Get completed print tasks count failed: " << e.what() << std::endl;
            return 0;
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

        auto users = get_all_users();
        std::cout << "User count: " << users.size() << std::endl;

        auto customers = get_all_customers();
        std::cout << "Customer count: " << customers.size() << std::endl;

        auto orders = get_all_orders();
        std::cout << "Order count: " << orders.size() << std::endl;

        auto print_tasks = get_all_print_tasks();
        std::cout << "Print task count: " << print_tasks.size() << std::endl;

        int completed = get_completed_print_tasks_count();
        std::cout << "Completed print tasks: " << completed << std::endl;

        auto gcode_files = get_all_gcode_files();
        std::cout << "G-code file count: " << gcode_files.size() << std::endl;

        std::cout << "===============================================\n\n";
    }

    void lmDBCore::print(const std::string& query)
    {
        std::cout << "print start ---------------- \n";
        auto vec = impl->sqlite.query<User>(query);
        for (const auto& user : vec) {
            std::cout << user.id << ", "  << ", " << user.name << ", " 
                      << user.email << ", " << user.phone << ", role=" << user.role << "\n";
        }

        std::cout << "print end ------------------\n";
        std::cout << std::endl;
    }
}
