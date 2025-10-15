#pragma once

#include <string>
#include <vector>
#include <memory>
#include "lm/export.h"

namespace lm {
namespace crypto {

/**
 * @brief AES-256加密解密工具类
 * 
 * 提供AES-256-CBC模式的加密和解密功能
 * 使用PKCS7填充和随机IV
 */
class LM_DB_API AESEncryption {
public:
    static constexpr size_t KEY_SIZE = 32;  // AES-256密钥长度
    static constexpr size_t IV_SIZE = 16;   // AES块大小
    static constexpr size_t BLOCK_SIZE = 16; // AES块大小

    /**
     * @brief 构造函数
     * @param key 32字节的加密密钥
     */
    explicit AESEncryption(const std::vector<uint8_t>& key);
    
    /**
     * @brief 从字符串生成密钥
     * @param password 密码字符串
     * @return 生成的密钥
     */
    static std::vector<uint8_t> generateKeyFromPassword(const std::string& password);
    
    /**
     * @brief 生成随机密钥
     * @return 随机生成的32字节密钥
     */
    static std::vector<uint8_t> generateRandomKey();
    
    /**
     * @brief 加密数据
     * @param plaintext 明文数据
     * @return 加密后的数据（包含IV）
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    
    /**
     * @brief 解密数据
     * @param ciphertext 密文数据（包含IV）
     * @return 解密后的明文数据
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    
    /**
     * @brief 加密字符串
     * @param plaintext 明文字符串
     * @return Base64编码的加密数据
     */
    std::string encryptString(const std::string& plaintext);
    
    /**
     * @brief 解密字符串
     * @param ciphertext Base64编码的密文
     * @return 解密后的明文字符串
     */
    std::string decryptString(const std::string& ciphertext);
    
    /**
     * @brief 加密文件
     * @param inputPath 输入文件路径
     * @param outputPath 输出文件路径
     * @return 是否成功
     */
    bool encryptFile(const std::string& inputPath, const std::string& outputPath);
    
    /**
     * @brief 解密文件
     * @param inputPath 输入文件路径
     * @param outputPath 输出文件路径
     * @return 是否成功
     */
    bool decryptFile(const std::string& inputPath, const std::string& outputPath);

private:
    std::vector<uint8_t> key_;
    
    /**
     * @brief Base64编码
     */
    std::string base64Encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief Base64解码
     */
    std::vector<uint8_t> base64Decode(const std::string& encoded);
    
    /**
     * @brief 生成随机IV
     */
    static std::vector<uint8_t> generateIV();
};

} // namespace crypto
} // namespace lm
