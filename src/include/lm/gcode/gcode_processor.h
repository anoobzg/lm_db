#pragma once

#include "lm/crypto/aes_encryption.h"
#include "lm/export.h"
#include <string>
#include <vector>
#include <memory>
#include <fstream>

namespace lm {
namespace gcode {

/**
 * @brief G-code文件处理器
 * 
 * 提供G-code文件的加密、解密和验证功能
 */
class LM_DB_API GCodeProcessor {
public:
    /**
     * @brief 构造函数
     * @param encryption 加密器实例
     */
    explicit GCodeProcessor(std::shared_ptr<crypto::AESEncryption> encryption);
    
    /**
     * @brief 从密码创建处理器
     * @param password 加密密码
     */
    explicit GCodeProcessor(const std::string& password);
    
    /**
     * @brief 加密G-code文件
     * @param inputPath 输入G-code文件路径
     * @param outputPath 输出加密文件路径
     * @return 是否成功
     */
    bool encryptGCodeFile(const std::string& inputPath, const std::string& outputPath);
    
    /**
     * @brief 解密G-code文件
     * @param inputPath 输入加密文件路径
     * @param outputPath 输出G-code文件路径
     * @return 是否成功
     */
    bool decryptGCodeFile(const std::string& inputPath, const std::string& outputPath);
    
    /**
     * @brief 验证G-code文件格式
     * @param filePath G-code文件路径
     * @return 是否为有效的G-code文件
     */
    static bool validateGCodeFile(const std::string& filePath);
    
    /**
     * @brief 获取G-code文件信息
     * @param filePath G-code文件路径
     * @return 文件信息字符串
     */
    static std::string getGCodeFileInfo(const std::string& filePath);
    
    /**
     * @brief 创建示例G-code文件
     * @param filePath 输出文件路径
     * @return 是否成功
     */
    static bool createSampleGCodeFile(const std::string& filePath);

private:
    std::shared_ptr<crypto::AESEncryption> encryption_;
    
    /**
     * @brief 检查是否为G-code命令
     */
    static bool isGCodeCommand(const std::string& line);
    
    /**
     * @brief 统计G-code命令
     */
    static std::vector<std::pair<std::string, int>> countGCodeCommands(const std::string& filePath);
};

} // namespace gcode
} // namespace lm

