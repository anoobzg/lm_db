#include "lm/crypto/aes_encryption.h"
#include "lm/gcode/gcode_processor.h"
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <iomanip>

using namespace lm::crypto;
using namespace lm::gcode;

void printMenu() {
    std::cout << "\n=== AES-256 G-code 文件加密解密程序 ===\n";
    std::cout << "1. 创建示例G-code文件\n";
    std::cout << "2. 加密G-code文件\n";
    std::cout << "3. 解密G-code文件\n";
    std::cout << "4. 查看G-code文件信息\n";
    std::cout << "5. 验证G-code文件格式\n";
    std::cout << "6. 测试字符串加密解密\n";
    std::cout << "7. 生成随机密钥\n";
    std::cout << "0. 退出\n";
    std::cout << "请选择操作: ";
}

void createSampleGCode() {
    std::string filename;
    std::cout << "请输入示例G-code文件名 (默认: sample.gcode): ";
    std::getline(std::cin, filename);
    
    if (filename.empty()) {
        filename = "sample.gcode";
    }
    
    if (GCodeProcessor::createSampleGCodeFile(filename)) {
        std::cout << "示例G-code文件创建成功: " << filename << std::endl;
        
        // 显示文件信息
        std::cout << "\n文件信息:\n";
        std::cout << GCodeProcessor::getGCodeFileInfo(filename) << std::endl;
    } else {
        std::cout << "创建示例G-code文件失败!" << std::endl;
    }
}

void encryptGCodeFile() {
    std::string inputFile, outputFile, password;
    
    std::cout << "请输入要加密的G-code文件路径: ";
    std::getline(std::cin, inputFile);
    
    if (!std::filesystem::exists(inputFile)) {
        std::cout << "文件不存在: " << inputFile << std::endl;
        return;
    }
    
    std::cout << "请输入加密后的输出文件路径: ";
    std::getline(std::cin, outputFile);
    
    std::cout << "请输入加密密码: ";
    std::getline(std::cin, password);
    
    if (password.empty()) {
        std::cout << "密码不能为空!" << std::endl;
        return;
    }
    
    try {
        GCodeProcessor processor(password);
        
        if (processor.encryptGCodeFile(inputFile, outputFile)) {
            std::cout << "G-code文件加密成功!" << std::endl;
            std::cout << "加密文件: " << outputFile << std::endl;
            
            // 显示文件大小对比
            auto inputSize = std::filesystem::file_size(inputFile);
            auto outputSize = std::filesystem::file_size(outputFile);
            std::cout << "原文件大小: " << inputSize << " 字节" << std::endl;
            std::cout << "加密文件大小: " << outputSize << " 字节" << std::endl;
        } else {
            std::cout << "G-code文件加密失败!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "加密过程中发生错误: " << e.what() << std::endl;
    }
}

void decryptGCodeFile() {
    std::string inputFile, outputFile, password;
    
    std::cout << "请输入要解密的加密文件路径: ";
    std::getline(std::cin, inputFile);
    
    if (!std::filesystem::exists(inputFile)) {
        std::cout << "文件不存在: " << inputFile << std::endl;
        return;
    }
    
    std::cout << "请输入解密后的输出文件路径: ";
    std::getline(std::cin, outputFile);
    
    std::cout << "请输入解密密码: ";
    std::getline(std::cin, password);
    
    if (password.empty()) {
        std::cout << "密码不能为空!" << std::endl;
        return;
    }
    
    try {
        GCodeProcessor processor(password);
        
        if (processor.decryptGCodeFile(inputFile, outputFile)) {
            std::cout << "G-code文件解密成功!" << std::endl;
            std::cout << "解密文件: " << outputFile << std::endl;
            
            // 显示文件信息
            std::cout << "\n解密后的文件信息:\n";
            std::cout << GCodeProcessor::getGCodeFileInfo(outputFile) << std::endl;
        } else {
            std::cout << "G-code文件解密失败! 请检查密码是否正确。" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "解密过程中发生错误: " << e.what() << std::endl;
    }
}

void showGCodeFileInfo() {
    std::string filename;
    std::cout << "请输入G-code文件路径: ";
    std::getline(std::cin, filename);
    
    if (!std::filesystem::exists(filename)) {
        std::cout << "文件不存在: " << filename << std::endl;
        return;
    }
    
    std::cout << GCodeProcessor::getGCodeFileInfo(filename) << std::endl;
}

void validateGCodeFile() {
    std::string filename;
    std::cout << "请输入G-code文件路径: ";
    std::getline(std::cin, filename);
    
    if (!std::filesystem::exists(filename)) {
        std::cout << "文件不存在: " << filename << std::endl;
        return;
    }
    
    if (GCodeProcessor::validateGCodeFile(filename)) {
        std::cout << "文件是有效的G-code文件!" << std::endl;
    } else {
        std::cout << "文件不是有效的G-code文件!" << std::endl;
    }
}

void testStringEncryption() {
    std::string text, password;
    
    std::cout << "请输入要加密的文本: ";
    std::getline(std::cin, text);
    
    std::cout << "请输入加密密码: ";
    std::getline(std::cin, password);
    
    if (text.empty() || password.empty()) {
        std::cout << "文本和密码都不能为空!" << std::endl;
        return;
    }
    
    try {
        auto key = AESEncryption::generateKeyFromPassword(password);
        AESEncryption encryption(key);
        
        std::string encrypted = encryption.encryptString(text);
        std::string decrypted = encryption.decryptString(encrypted);
        
        std::cout << "\n原始文本: " << text << std::endl;
        std::cout << "加密结果: " << encrypted << std::endl;
        std::cout << "解密结果: " << decrypted << std::endl;
        
        if (text == decrypted) {
            std::cout << "✓ 加密解密测试成功!" << std::endl;
        } else {
            std::cout << "✗ 加密解密测试失败!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "字符串加密解密过程中发生错误: " << e.what() << std::endl;
    }
}

void generateRandomKey() {
    try {
        auto key = AESEncryption::generateRandomKey();
        
        std::cout << "生成的随机密钥 (32字节):\n";
        std::cout << "十六进制: ";
        for (uint8_t byte : key) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;
        
        std::cout << "Base64: ";
        std::vector<uint8_t> keyVec(key.begin(), key.end());
        AESEncryption temp(keyVec);
        std::string base64Key = temp.base64Encode(keyVec);
        std::cout << base64Key << std::endl;
    } catch (const std::exception& e) {
        std::cout << "生成随机密钥时发生错误: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "欢迎使用 AES-256 G-code 文件加密解密程序!" << std::endl;
    
    int choice;
    while (true) {
        printMenu();
        std::cin >> choice;
        std::cin.ignore(); // 清除输入缓冲区
        
        switch (choice) {
            case 1:
                createSampleGCode();
                break;
            case 2:
                encryptGCodeFile();
                break;
            case 3:
                decryptGCodeFile();
                break;
            case 4:
                showGCodeFileInfo();
                break;
            case 5:
                validateGCodeFile();
                break;
            case 6:
                testStringEncryption();
                break;
            case 7:
                generateRandomKey();
                break;
            case 0:
                std::cout << "感谢使用，再见!" << std::endl;
                return 0;
            default:
                std::cout << "无效的选择，请重新输入!" << std::endl;
                break;
        }
        
        std::cout << "\n按回车键继续...";
        std::cin.get();
    }
    
    return 0;
}
