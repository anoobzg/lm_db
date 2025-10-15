#pragma once

#include "gcode_file_model.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>

namespace lm {
namespace database {

/**
 * @brief G-code文件数据库管理器
 */
class GCodeDatabaseManager {
public:
    /**
     * @brief 构造函数
     * @param dbPath 数据库文件路径
     */
    explicit GCodeDatabaseManager(const std::string& dbPath);
    
    /**
     * @brief 析构函数
     */
    ~GCodeDatabaseManager();
    
    /**
     * @brief 初始化数据库
     * @return 是否成功
     */
    bool initialize();
    
    /**
     * @brief 关闭数据库连接
     */
    void close();
    
    // G-code文件管理
    /**
     * @brief 添加G-code文件记录
     * @param gcodeFile G-code文件信息
     * @return 新记录的ID，失败返回-1
     */
    int addGCodeFile(const GCodeFile& gcodeFile);
    
    /**
     * @brief 更新G-code文件记录
     * @param gcodeFile G-code文件信息
     * @return 是否成功
     */
    bool updateGCodeFile(const GCodeFile& gcodeFile);
    
    /**
     * @brief 删除G-code文件记录
     * @param id 文件ID
     * @return 是否成功
     */
    bool deleteGCodeFile(int id);
    
    /**
     * @brief 根据ID获取G-code文件
     * @param id 文件ID
     * @return G-code文件信息，不存在返回nullopt
     */
    std::optional<GCodeFile> getGCodeFileById(int id);
    
    /**
     * @brief 根据文件名获取G-code文件
     * @param filename 文件名
     * @return G-code文件信息，不存在返回nullopt
     */
    std::optional<GCodeFile> getGCodeFileByName(const std::string& filename);
    
    /**
     * @brief 根据文件哈希获取G-code文件
     * @param fileHash 文件哈希
     * @return G-code文件信息，不存在返回nullopt
     */
    std::optional<GCodeFile> getGCodeFileByHash(const std::string& fileHash);
    
    /**
     * @brief 获取所有G-code文件
     * @return G-code文件列表
     */
    std::vector<GCodeFile> getAllGCodeFiles();
    
    /**
     * @brief 搜索G-code文件
     * @param keyword 搜索关键词
     * @return 匹配的G-code文件列表
     */
    std::vector<GCodeFile> searchGCodeFiles(const std::string& keyword);
    
    /**
     * @brief 根据标签搜索G-code文件
     * @param tagName 标签名称
     * @return 匹配的G-code文件列表
     */
    std::vector<GCodeFile> getGCodeFilesByTag(const std::string& tagName);
    
    /**
     * @brief 获取收藏的G-code文件
     * @return 收藏的G-code文件列表
     */
    std::vector<GCodeFile> getFavoriteGCodeFiles();
    
    /**
     * @brief 获取最近访问的G-code文件
     * @param limit 限制数量
     * @return 最近访问的G-code文件列表
     */
    std::vector<GCodeFile> getRecentGCodeFiles(int limit = 10);
    
    /**
     * @brief 获取最受欢迎的G-code文件
     * @param limit 限制数量
     * @return 最受欢迎的G-code文件列表
     */
    std::vector<GCodeFile> getPopularGCodeFiles(int limit = 10);
    
    // 标签管理
    /**
     * @brief 添加标签
     * @param tag 标签信息
     * @return 新标签的ID，失败返回-1
     */
    int addTag(const GCodeTag& tag);
    
    /**
     * @brief 获取所有标签
     * @return 标签列表
     */
    std::vector<GCodeTag> getAllTags();
    
    /**
     * @brief 为G-code文件添加标签
     * @param gcodeFileId G-code文件ID
     * @param tagId 标签ID
     * @return 是否成功
     */
    bool addTagToGCodeFile(int gcodeFileId, int tagId);
    
    /**
     * @brief 从G-code文件移除标签
     * @param gcodeFileId G-code文件ID
     * @param tagId 标签ID
     * @return 是否成功
     */
    bool removeTagFromGCodeFile(int gcodeFileId, int tagId);
    
    /**
     * @brief 获取G-code文件的所有标签
     * @param gcodeFileId G-code文件ID
     * @return 标签列表
     */
    std::vector<GCodeTag> getTagsForGCodeFile(int gcodeFileId);
    
    // 访问记录管理
    /**
     * @brief 记录文件访问
     * @param access 访问记录
     * @return 是否成功
     */
    bool recordAccess(const GCodeAccess& access);
    
    /**
     * @brief 记录文件下载
     * @param download 下载记录
     * @return 是否成功
     */
    bool recordDownload(const GCodeDownload& download);
    
    /**
     * @brief 获取文件的访问统计
     * @param gcodeFileId G-code文件ID
     * @return 访问次数
     */
    int getAccessCount(int gcodeFileId);
    
    /**
     * @brief 获取文件的下载统计
     * @param gcodeFileId G-code文件ID
     * @return 下载次数
     */
    int getDownloadCount(int gcodeFileId);
    
    // 统计信息
    /**
     * @brief 获取数据库统计信息
     * @return 统计信息字符串
     */
    std::string getDatabaseStats();
    
    /**
     * @brief 获取文件大小统计
     * @return 总文件大小（字节）
     */
    long getTotalFileSize();
    
    /**
     * @brief 获取文件数量统计
     * @return 文件总数
     */
    int getTotalFileCount();

private:
    std::string dbPath_;
    std::unique_ptr<ormpp::dbng<ormpp::sqlite>> db_;
    
    /**
     * @brief 创建数据库表
     * @return 是否成功
     */
    bool createTables();
    
    /**
     * @brief 创建索引
     * @return 是否成功
     */
    bool createIndexes();
    
    /**
     * @brief 更新文件访问时间
     * @param gcodeFileId G-code文件ID
     */
    void updateLastAccessed(int gcodeFileId);
};

} // namespace database
} // namespace lm

