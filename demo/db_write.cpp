#include "lm/kernel/lmuserdb.h"
#include "lm/crypto/aes_encryption.h"
#include "lm/gcode/gcode_processor.h"
#include <iostream>
#include <string>
#include <vector>
#include <io.h>
#include <direct.h>

using namespace lmdb;
using namespace lm::crypto;
using namespace lm::gcode;

int main() 
{
 
    if (_access("data", 0) != 0) {
        _mkdir("data");
    }
    if (_access("resource", 0) != 0) {
        _mkdir("resource");
    }
    if (_access("enc_resource", 0) != 0) {
        _mkdir("enc_resource");
    }
    
    lmdb::LMUserDB userDB("data\\print3d.db");

    // Initialize database with all tables
    if (!userDB.initialize()) {
        std::cerr << "Failed to initialize database!" << std::endl;
        return 1;
    }

    std::cout << "Database initialized successfully!" << std::endl;

    // Test admin operations
    userDB.add_admin("admin", "admin123", "super_admin");
    userDB.add_admin("manager", "manager456", "manager");
    
    // Test legacy user operations (backward compatibility)
    userDB.clear_users();
    userDB.add_user("alice", "Alice's account");
    userDB.set_password("alice", "password123");
    userDB.add_user("bob", "Bob's account");
    userDB.set_password("bob", "securepass");
    userDB.add_user("charlie", "Charlie's account");
    userDB.set_password("charlie", "charliepwd");

    // Test customer operations
    userDB.add_customer("Customer A", "123-456-7890");
    userDB.add_customer("Customer B", "098-765-4321");

    // Test order operations
    userDB.add_order(1, "Order 001", "First test order");
    userDB.add_order(1, "Order 002", "Second test order");
    userDB.add_order(2, "Order 003", "Third test order");

    // Test print task operations
    userDB.add_print_task(1, "Print Task 1", "model1.gcode", 10);
    userDB.add_print_task(1, "Print Task 2", "model2.gcode", 5);
    userDB.add_print_task(2, "Print Task 3", "model3.gcode", 15);

    // Update print progress
    userDB.update_print_progress(1, 5); // 50% complete
    userDB.update_print_progress(2, 5); // 100% complete

    // Test G-code file operations
    std::cout << "\n=== Testing G-code File Operations ===" << std::endl;
    
    // Test creating and encrypting actual G-code file
    std::cout << "\n--- Testing G-code File Creation and Encryption ---" << std::endl;
    
    std::string sampleFile = "resource\\real_test.gcode";
    if (GCodeProcessor::createSampleGCodeFile(sampleFile)) {
        std::cout << "✓ Created sample G-code file: " << sampleFile << std::endl;
        
        // Generate random password for encryption
        auto randomKey = AESEncryption::generateRandomKey();
        std::string randomPassword(randomKey.begin(), randomKey.end());
        std::cout << "✓ Generated random password for encryption" << std::endl;
        
        std::string encryptedFile = "enc_resource\\real_test.gcode.enc";
        
        GCodeProcessor processor(randomPassword);
        if (processor.encryptGCodeFile(sampleFile, encryptedFile)) {
            std::cout << "✓ Successfully encrypted G-code file" << std::endl;
            
            // Store encrypted file info to database with the random password as aeskey
            if (userDB.add_gcode_file("real_test.gcode", encryptedFile, randomPassword)) {
                std::cout << "✓ Successfully stored encrypted file info to database" << std::endl;
            } else {
                std::cout << "✗ Failed to store file info to database" << std::endl;
            }
        } else {
            std::cout << "✗ Failed to encrypt G-code file" << std::endl;
        }
         
    } else {
        std::cout << "✗ Failed to create sample G-code file" << std::endl;
    }
    
    // Test G-code file decryption
    std::cout << "\n--- Testing G-code File Decryption ---" << std::endl;
    
    std::string encryptedFilePath = "enc_resource\\real_test.gcode.enc";
    std::string decryptedFilePath = "enc_resource\\real_test.gcode";
    
    
    // 从数据库读取 aeskey 进行解密
    auto foundFile = userDB.get_gcode_file_by_filename("real_test.gcode");
    if (foundFile.id != 0) {
        std::cout << "✓ Found file in database, using stored aeskey for decryption" << std::endl;
     
        GCodeProcessor decryptProcessor(foundFile.aeskey);
        if (decryptProcessor.decryptGCodeFile(encryptedFilePath, decryptedFilePath)) {
            std::cout << "✓ Successfully decrypted G-code file to: " << decryptedFilePath << std::endl;
        } else {
            std::cout << "✗ Failed to decrypt G-code file" << std::endl;
        }
    } else {
        std::cout << "✗ File not found in database" << std::endl;
    }
    
    // // Test G-code file retrieval
    // std::cout << "\n--- Testing G-code File Retrieval ---" << std::endl;
    // auto allFiles = userDB.get_all_gcode_files();
    // std::cout << "Total G-code files in database: " << allFiles.size() << std::endl;
    
    // for (const auto& file : allFiles) {
    //     std::cout << "  ID: " << file.id 
    //               << ", Filename: " << file.filename
    //               << ", Encrypted Path: " << file.encrypted_path
    //               << ", Upload Time: " << file.upload_time << std::endl;
    // }
    
    // // Test finding G-code file by filename
    // std::string searchFilename = "test_model_1.gcode";
    // auto foundFile1 = userDB.get_gcode_file_by_filename(searchFilename);
    // if (foundFile1.id != 0) {
    //     std::cout << "✓ Found G-code file: " << foundFile1.filename << std::endl;
    // } else {
    //     std::cout << "✗ G-code file not found: " << searchFilename << std::endl;
    // }

    // // Print database status
    // userDB.print_database_status();

    // std::cout << "All operations completed successfully!" << std::endl;
    return 0;
}