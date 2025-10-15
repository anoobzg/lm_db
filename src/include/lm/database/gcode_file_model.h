#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <ormpp/dbng.hpp>
#include <ormpp/mysql.hpp>
#include <ormpp/sqlite.hpp>

namespace lm {
namespace database {

/**
 * @brief G-code文件数据库模型
 */
struct GCodeFile {
    int id = 0;                                    // 主键ID
    std::string filename;                          // 文件名
    std::string original_path;                     // 原始文件路径
    std::string encrypted_path;                    // 加密文件路径
    std::string file_hash;                         // 文件哈希值
    std::string encryption_key_hash;               // 加密密钥哈希
    std::string description;                       // 文件描述
    std::string tags;                              // 标签（逗号分隔）
    long file_size = 0;                           // 文件大小（字节）
    int layer_count = 0;                          // 层数
    double print_time_estimate = 0.0;             // 预计打印时间（分钟）
    std::string material_type;                     // 材料类型
    double layer_height = 0.0;                    // 层高
    double infill_percentage = 0.0;               // 填充百分比
    std::string printer_model;                     // 打印机型号
    std::string nozzle_diameter;                   // 喷嘴直径
    std::string print_temperature;                 // 打印温度
    std::string bed_temperature;                   // 热床温度
    std::string print_speed;                       // 打印速度
    std::string created_by;                        // 创建者
    std::string last_modified_by;                  // 最后修改者
    std::chrono::system_clock::time_point created_at;      // 创建时间
    std::chrono::system_clock::time_point updated_at;      // 更新时间
    std::chrono::system_clock::time_point last_accessed;   // 最后访问时间
    bool is_encrypted = false;                     // 是否已加密
    bool is_favorite = false;                      // 是否收藏
    int download_count = 0;                        // 下载次数
    double rating = 0.0;                          // 评分
    std::string notes;                             // 备注
    std::string thumbnail_path;                    // 缩略图路径
    std::string preview_images;                    // 预览图片路径（JSON格式）
    std::string gcode_commands;                    // G-code命令统计（JSON格式）
    std::string metadata;                          // 其他元数据（JSON格式）
};

/**
 * @brief G-code文件标签模型
 */
struct GCodeTag {
    int id = 0;                                    // 主键ID
    std::string name;                              // 标签名称
    std::string color;                             // 标签颜色
    std::string description;                       // 标签描述
    std::chrono::system_clock::time_point created_at;      // 创建时间
};

/**
 * @brief G-code文件与标签关联模型
 */
struct GCodeFileTag {
    int id = 0;                                    // 主键ID
    int gcode_file_id = 0;                         // G-code文件ID
    int tag_id = 0;                                // 标签ID
    std::chrono::system_clock::time_point created_at;      // 创建时间
};

/**
 * @brief G-code文件下载记录模型
 */
struct GCodeDownload {
    int id = 0;                                    // 主键ID
    int gcode_file_id = 0;                         // G-code文件ID
    std::string downloaded_by;                     // 下载者
    std::string download_ip;                       // 下载IP
    std::string user_agent;                        // 用户代理
    std::chrono::system_clock::time_point downloaded_at;   // 下载时间
    long download_size = 0;                        // 下载大小
    std::string download_type;                     // 下载类型（original/encrypted）
};

/**
 * @brief G-code文件访问记录模型
 */
struct GCodeAccess {
    int id = 0;                                    // 主键ID
    int gcode_file_id = 0;                         // G-code文件ID
    std::string accessed_by;                       // 访问者
    std::string access_type;                       // 访问类型（view/edit/download）
    std::string access_ip;                         // 访问IP
    std::chrono::system_clock::time_point accessed_at;     // 访问时间
    std::string user_agent;                        // 用户代理
    std::string notes;                             // 备注
};

} // namespace database
} // namespace lm

