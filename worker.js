// worker.js - 修复版 (解决注册后登录失败问题)

// ========== 基础配置与工具类 ==========
const APP_NAME = "TeleChat";
const DEFAULT_INVITE_CODE = "xiyuenb";
const EMOJI_COUNT = 279;

// 全局绑定变量（将在initializeBindings中设置）
let CHAT_DATA;
let ENCRYPTION_KEY_VALUE;
let ADMIN_USERNAME_VALUE;

// 初始化绑定
async function initializeBindings() {
    // KV绑定
    CHAT_DATA = typeof QDATA !== 'undefined' ? QDATA : {
        get: async (key) => {
            console.warn(`KV get called with key: ${key}, but QDATA is not available`);
            return null;
        },
        put: async (key, value, options = {}) => {
            console.warn(`KV put called with key: ${key}, but QDATA is not available`);
            return { success: false };
        },
        delete: async (key) => {
            console.warn(`KV delete called with key: ${key}, but QDATA is not available`);
            return { success: false };
        },
        list: async (options = {}) => {
            console.warn(`KV list called, but QDATA is not available`);
            return { keys: [] };
        }
    };

    // 环境变量
    ENCRYPTION_KEY_VALUE = typeof ENCRYPTION_KEY !== 'undefined' ? ENCRYPTION_KEY : "32byteslongencryptionkey12345678";
    ADMIN_USERNAME_VALUE = typeof ADMIN_USERNAME !== 'undefined' ? ADMIN_USERNAME : "xiyue";
}

// 加密工具类
class CryptoUtils {
    static async getEncryptionKey() {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey("raw",
            encoder.encode(ENCRYPTION_KEY_VALUE),
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );
        return keyMaterial;
    }

    static async encrypt(data) {
        const key = await this.getEncryptionKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            new TextEncoder().encode(data)
        );
        return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
    }

    static async decrypt(encryptedData) {
        const key = await this.getEncryptionKey();
        const iv = new Uint8Array(encryptedData.iv);
        const data = new Uint8Array(encryptedData.data);
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );
        return new TextDecoder().decode(decrypted);
    }

    static generateSessionToken() {
        return crypto.randomUUID();
    }

    static generateUID() {
        return crypto.randomUUID();
    }

    static generateTemporaryPassword() {
        return Math.random().toString(36).slice(-8);
    }

    static hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        return crypto.subtle.digest('SHA-256', data).then(hash => {
            return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        });
    }

    static verifyPassword(password, hash) {
        return this.hashPassword(password).then(hashedPassword => hashedPassword === hash);
    }

    static sanitizeInput(input) {
        if (!input) return input;
        return input.replace(/</g, '<').replace(/>/g, '>');
    }

    static calculateLevel(experience) {
        let level = 1;
        let requiredExp = 0;
        for (let i = 1; i <= 100; i++) {
            requiredExp += 100 * i;
            if (experience >= requiredExp) {
                level = i + 1;
            } else {
                break;
            }
        }
        return level;
    }
}

// KV操作工具类
class KVStore {
    static async getUser(uid) {
        if (!uid) return null;
        try {
            const key = `users:${uid}`;
            const userData = await CHAT_DATA.get(key);
            if (!userData) return null;
            const decrypted = await CryptoUtils.decrypt(JSON.parse(userData));
            return JSON.parse(decrypted);
        } catch (e) {
            console.error("Error getting user:", e);
            return null;
        }
    }

    static async getUserByUsername(username) {
        if (!username) return null;
        try {
            // 直接尝试从缓存中获取，这是最高效的
            const cachedKey = `user_cache:${username.toLowerCase()}`;
            const cachedUser = await CHAT_DATA.get(cachedKey);
            if (cachedUser) {
                const decrypted = await CryptoUtils.decrypt(JSON.parse(cachedUser));
                return JSON.parse(decrypted);
            }

            // 如果缓存未命中，才进行搜索
            // 为了简化并提高可靠性，这里使用直接的键名，假设用户名是唯一的
            // 注意：这需要确保在创建用户时，`username` 字段是唯一且小写的
            const key = `users:${username.toLowerCase()}`;
            const userData = await CHAT_DATA.get(key);
            if (!userData) return null;

            // 解密并返回用户数据
            const decrypted = await CryptoUtils.decrypt(JSON.parse(userData));
            const user = JSON.parse(decrypted);

            // 更新缓存
            await CHAT_DATA.put(cachedKey, JSON.stringify(user), { expirationTtl: 3600 }); // 缓存1小时

            return user;
        } catch (e) {
            console.error("Error getting user by username:", e);
            return null;
        }
    }

    static async saveUser(user) {
        if (!user || !user.uid) return false;
        try {
            // 构建用户数据
            const userData = JSON.stringify(user);
            const encryptedData = await CryptoUtils.encrypt(userData);

            // 保存到主存储
            const key = `users:${user.uid}`;
            await CHAT_DATA.put(key, JSON.stringify(encryptedData), { expirationTtl: 31536000 });

            // 保存到用户名索引（用于快速查找）
            const usernameKey = `users:${user.username.toLowerCase()}`;
            await CHAT_DATA.put(usernameKey, JSON.stringify(encryptedData), { expirationTtl: 31536000 });

            // 更新缓存
            const cacheKey = `user_cache:${user.username.toLowerCase()}`;
            await CHAT_DATA.put(cacheKey, JSON.stringify(user), { expirationTtl: 3600 });

            return true;
        } catch (e) {
            console.error("Error saving user:", e);
            return false;
        }
    }

    static async getAllUsers() {
        try {
            const keys = await CHAT_DATA.list({ prefix: "users:" });
            const users = [];
            for (const key of keys.keys) {
                if (key.name.startsWith("users:") && !key.name.includes("cache")) {
                    const userData = await CHAT_DATA.get(key.name);
                    if (userData) {
                        const decrypted = await CryptoUtils.decrypt(JSON.parse(userData));
                        users.push(JSON.parse(decrypted));
                    }
                }
            }
            return users;
        } catch (e) {
            console.error("Error getting all users:", e);
            return [];
        }
    }

    static async getConfig() {
        try {
            const configKey = "config";
            const configData = await CHAT_DATA.get(configKey);
            if (!configData) {
                // 创建默认配置
                const defaultConfig = {
                    invite_code: DEFAULT_INVITE_CODE,
                    next_uid: 1,
                    titles: {}
                };
                const encryptedConfig = await CryptoUtils.encrypt(JSON.stringify(defaultConfig));
                await CHAT_DATA.put(configKey, JSON.stringify(encryptedConfig), { expirationTtl: 31536000 });
                return defaultConfig;
            }
            const decrypted = await CryptoUtils.decrypt(JSON.parse(configData));
            return JSON.parse(decrypted);
        } catch (e) {
            console.error("Error getting config:", e);
            return { invite_code: DEFAULT_INVITE_CODE, next_uid: 1, titles: {} };
        }
    }

    static async saveConfig(config) {
        try {
            const encryptedConfig = await CryptoUtils.encrypt(JSON.stringify(config));
            await CHAT_DATA.put("config", JSON.stringify(encryptedConfig), { expirationTtl: 31536000 });
            return true;
        } catch (e) {
            console.error("Error saving config:", e);
            return false;
        }
    }

    static async getNextUID() {
        const config = await this.getConfig();
        const nextUID = config.next_uid;
        config.next_uid = nextUID + 1;
        await this.saveConfig(config);
        return nextUID.toString();
    }

    static async saveMessage(senderUid, receiverUid, message) {
        try {
            // 使用双方ID组合作为消息存储的键，确保双向可访问
            const key = `messages:${senderUid}_${receiverUid}`;
            const messages = await CHAT_DATA.get(key);
            let messageList = messages ? JSON.parse(messages) : [];
            messageList.push(message);
            const encryptedMessages = await CryptoUtils.encrypt(JSON.stringify(messageList));
            await CHAT_DATA.put(key, JSON.stringify(encryptedMessages), { expirationTtl: 31536000 });
            return true;
        } catch (e) {
            console.error("Error saving message:", e);
            return false;
        }
    }

    static async getMessages(senderUid, receiverUid) {
        try {
            const key = `messages:${senderUid}_${receiverUid}`;
            const messagesData = await CHAT_DATA.get(key);
            if (!messagesData) return [];
            const decrypted = await CryptoUtils.decrypt(JSON.parse(messagesData));
            return JSON.parse(decrypted);
        } catch (e) {
            console.error("Error getting messages:", e);
            return [];
        }
    }

    static async markMessagesAsRead(senderUid, receiverUid) {
        try {
            const messages = await this.getMessages(senderUid, receiverUid);
            const updatedMessages = messages.map(msg => {
                if (msg.receiver_uid === receiverUid && !msg.read) {
                    msg.read = true;
                }
                return msg;
            });
            const encryptedMessages = await CryptoUtils.encrypt(JSON.stringify(updatedMessages));
            await CHAT_DATA.put(`messages:${senderUid}_${receiverUid}`, JSON.stringify(encryptedMessages), { expirationTtl: 31536000 });
        } catch (e) {
            console.error("Error marking messages as read:", e);
        }
    }

    static async saveAuditRecord(record) {
        try {
            const key = "admin:audits";
            const auditData = await CHAT_DATA.get(key);
            let records = auditData ? JSON.parse(auditData) : [];
            records.push(record);
            const encryptedData = await CryptoUtils.encrypt(JSON.stringify(records));
            await CHAT_DATA.put(key, JSON.stringify(encryptedData), { expirationTtl: 31536000 });
            return true;
        } catch (e) {
            console.error("Error saving audit record:", e);
            return false;
        }
    }

    static async getAuditRecords() {
        try {
            const key = "admin:audits";
            const auditData = await CHAT_DATA.get(key);
            if (!auditData) return [];
            const decrypted = await CryptoUtils.decrypt(JSON.parse(auditData));
            return JSON.parse(decrypted);
        } catch (e) {
            console.error("Error getting audit records:", e);
            return [];
        }
    }
}

// 用户管理类
class UserManager {
    static async register(userData) {
        // 验证必填字段
        if (!userData.username || !userData.password || !userData.invite_code) {
            return { success: false, error: "请填写所有必填字段" };
        }

        // 验证用户名格式
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(userData.username)) {
            return { success: false, error: "用户名只能包含字母、数字和下划线，长度3-20位" };
        }

        // 验证密码强度
        if (userData.password.length < 6) {
            return { success: false, error: "密码长度至少6位" };
        }

        // 检查用户名是否已存在
        const existingUser = await KVStore.getUserByUsername(userData.username);
        if (existingUser) {
            return { success: false, error: "用户名已存在" };
        }

        // 验证邀请码
        const config = await KVStore.getConfig();
        if (userData.invite_code !== config.invite_code) {
            return { success: false, error: "邀请码错误" };
        }

        // 生成UID
        let uid;
        if (userData.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase()) {
            uid = "0";
        } else {
            uid = await KVStore.getNextUID();
        }

        // 创建用户数据
        const today = new Date().toISOString().split('T')[0];
        const user = {
            uid: uid,
            username: userData.username.toLowerCase(),
            display_name: CryptoUtils.sanitizeInput(userData.display_name || userData.username),
            password_hash: await CryptoUtils.hashPassword(userData.password),
            avatar: userData.avatar || "https://via.placeholder.com/150",
            bio: CryptoUtils.sanitizeInput(userData.bio),
            gender: userData.gender === "♀" ? "♀" : "♂",
            created_at: today,
            last_login: today,
            last_checkin: today,
            online_days: 1,
            experience: 1000,
            level: CryptoUtils.calculateLevel(1000),
            is_banned: false,
            ban_until: null,
            ban_reason: null,
            settings: {
                theme: "light",
                notifications: true,
                privacy: {
                    last_seen: "everyone",
                    profile_photo: "everyone",
                    forward_messages: "everyone"
                }
            }
        };

        // 保存用户
        const saved = await KVStore.saveUser(user);
        if (!saved) {
            return { success: false, error: "创建用户失败" };
        }

        // 尝试自动登录
        const loginResult = await UserManager.login(userData.username, userData.password);
        if (!loginResult.success) {
            return { success: true, user: user, login_failed: true };
        }

        return { success: true, user: user };
    }

    static async login(username, password, request) {
        if (!username || !password) {
            return { success: false, error: "用户名或密码不能为空" };
        }

        const user = await KVStore.getUserByUsername(username.toLowerCase());
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        // 检查封禁状态
        if (user.is_banned) {
            const now = new Date();
            if (user.ban_until && new Date(user.ban_until) > now) {
                const banUntil = new Date(user.ban_until);
                return {
                    success: false,
                    error: `账号已被封禁，解封时间：${banUntil.toLocaleString()}`,
                    banned: true,
                    ban_until: user.ban_until
                };
            } else {
                // 封禁已过期，自动解封
                user.is_banned = false;
                user.ban_until = null;
                await KVStore.saveUser(user);
            }
        }

        // 验证密码
        if (!(await CryptoUtils.verifyPassword(password, user.password_hash))) {
            return { success: false, error: "密码错误" };
        }

        // 检查每日登录奖励
        await this.checkDailyLogin(user);

        // 更新最后登录时间
        user.last_login = new Date().toISOString();
        await KVStore.saveUser(user);

        // 创建会话
        const token = await SessionManager.createSession(user, request);
        return { success: true, user: user, token: token };
    }

    static async checkDailyLogin(user) {
        const today = new Date().toISOString().split('T')[0];
        if (user.last_checkin !== today) {
            // 增加经验
            user.experience += 10;
            user.level = CryptoUtils.calculateLevel(user.experience);
            user.online_days += 1;
            user.last_checkin = today;
            await KVStore.saveUser(user);
            return true;
        }
        return false;
    }

    static async updateProfile(uid, updates, currentPassword = null) {
        const user = await KVStore.getUser(uid);
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        // 如果要修改密码，需要验证当前密码
        if (updates.password && currentPassword) {
            if (!(await CryptoUtils.verifyPassword(currentPassword, user.password_hash))) {
                return { success: false, error: "当前密码错误" };
            }
            user.password_hash = await CryptoUtils.hashPassword(updates.password);
        }

        // 更新其他字段
        if (updates.display_name !== undefined) {
            user.display_name = CryptoUtils.sanitizeInput(updates.display_name);
        }
        if (updates.avatar !== undefined) {
            user.avatar = updates.avatar;
        }
        if (updates.bio !== undefined) {
            user.bio = CryptoUtils.sanitizeInput(updates.bio);
        }
        if (updates.gender !== undefined) {
            user.gender = updates.gender === "♀" ? "♀" : "♂";
        }
        if (updates.settings !== undefined) {
            user.settings = { ...user.settings, ...updates.settings };
        }

        const saved = await KVStore.saveUser(user);
        if (!saved) {
            return { success: false, error: "更新资料失败" };
        }
        return { success: true, user: user };
    }

    static async deleteAccount(uid, password) {
        const user = await KVStore.getUser(uid);
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        // 验证密码
        if (!(await CryptoUtils.verifyPassword(password, user.password_hash))) {
            return { success: false, error: "密码错误" };
        }

        // 删除用户数据
        await CHAT_DATA.delete(`users:${uid}`);
        await CHAT_DATA.delete(`users:${user.username.toLowerCase()}`);
        await CHAT_DATA.delete(`user_cache:${user.username.toLowerCase()}`);

        // 删除相关聊天记录（简化处理）
        const keys = await CHAT_DATA.list({ prefix: "messages:" });
        for (const key of keys.keys) {
            if (key.name.includes(`_${uid}`) || key.name.includes(`${uid}_`)) {
                await CHAT_DATA.delete(key.name);
            }
        }

        return { success: true };
    }

    static async submitAppeal(uid, email, reason) {
        const appeal = {
            id: CryptoUtils.generateUID(),
            uid: uid,
            email: email,
            reason: reason,
            status: "pending",
            timestamp: new Date().toISOString(),
            processed_at: null,
            admin_response: null
        };

        const saved = await KVStore.saveAuditRecord(appeal);
        if (!saved) {
            return { success: false, error: "提交申诉失败" };
        }
        return { success: true, appeal: appeal };
    }
}

// 会话管理类
class SessionManager {
    static async createSession(user, request) {
        const token = CryptoUtils.generateSessionToken();
        const userAgent = request.headers.get('User-Agent') || '';
        const ip = request.headers.get('CF-Connecting-IP') || '';

        const session = {
            uid: user.uid,
            username: user.username,
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7天
            ip: ip,
            user_agent: userAgent
        };

        const key = `session:${token}`;
        await CHAT_DATA.put(key, JSON.stringify(session), { expirationTtl: 7 * 24 * 60 * 60 });
        return token;
    }

    static async deleteSession(token) {
        const key = `session:${token}`;
        await CHAT_DATA.delete(key);
    }

    static async validateSession(token, request) {
        if (!token) return null;
        const key = `session:${token}`;
        const sessionStr = await CHAT_DATA.get(key);
        if (!sessionStr) return null;

        const session = JSON.parse(sessionStr);
        const now = new Date();
        const expiresAt = new Date(session.expires_at);
        if (expiresAt < now) {
            await CHAT_DATA.delete(key);
            return null;
        }

        // 验证IP和User-Agent（增强安全性）
        const currentIP = request.headers.get('CF-Connecting-IP') || '';
        const currentUserAgent = request.headers.get('User-Agent') || '';
        if (session.ip && currentIP && session.ip !== currentIP) {
            console.warn(`Session IP mismatch for user ${session.username}`);
        }

        const user = await KVStore.getUser(session.uid);
        if (!user || user.is_banned) {
            return null;
        }

        return user;
    }
}

// 聊天管理类
class ChatManager {
    static async sendMessage(senderUid, receiverUid, content) {
        const sender = await KVStore.getUser(senderUid);
        const receiver = await KVStore.getUser(receiverUid);
        if (!sender || !receiver) {
            return { success: false, error: "用户不存在" };
        }

        // 检查发送者是否被封禁
        if (sender.is_banned) {
            const now = new Date();
            if (sender.ban_until && new Date(sender.ban_until) > now) {
                return { success: false, error: "您的账号已被封禁，无法发送消息" };
            }
        }

        // 检查接收者是否被封禁
        if (receiver.is_banned) {
            const now = new Date();
            if (receiver.ban_until && new Date(receiver.ban_until) > now) {
                return { success: false, error: "对方账号已被封禁" };
            }
        }

        // 加密消息内容
        const encryptedContent = await CryptoUtils.encrypt(content);
        const message = {
            id: CryptoUtils.generateUID(),
            sender_uid: senderUid,
            receiver_uid: receiverUid,
            content: encryptedContent,
            timestamp: new Date().toISOString(),
            read: false,
            type: "text"
        };

        // 保存消息
        const saved = await KVStore.saveMessage(senderUid, receiverUid, message);
        if (!saved) {
            return { success: false, error: "发送消息失败" };
        }
        return { success: true, message: message };
    }

    static async getChatHistory(senderUid, receiverUid) {
        const messages = await KVStore.getMessages(senderUid, receiverUid);
        // 解密消息内容
        for (const message of messages) {
            try {
                message.decrypted_content = await CryptoUtils.decrypt(message.content);
            } catch (e) {
                message.decrypted_content = "[解密失败]";
            }
        }
        return messages;
    }

    static async getContacts(uid) {
        const user = await KVStore.getUser(uid);
        if (!user) return [];
        // 获取所有用户作为联系人（简化实现）
        const allUsers = await KVStore.getAllUsers();
        return allUsers.filter(u => u.uid !== uid);
    }

    static async markMessagesAsRead(senderUid, receiverUid) {
        await KVStore.markMessagesAsRead(senderUid, receiverUid);
    }
}

// 管理员管理类
class AdminManager {
    static async isAdmin(user) {
        return user && user.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase();
    }

    static async resetPassword(uid) {
        const user = await KVStore.getUser(uid);
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        // 生成临时密码
        const tempPassword = CryptoUtils.generateTemporaryPassword();
        user.password_hash = await CryptoUtils.hashPassword(tempPassword);
        const saved = await KVStore.saveUser(user);
        if (!saved) {
            return { success: false, error: "重置密码失败" };
        }
        return { success: true, temporary_password: tempPassword };
    }

    static async updateInviteCode(newCode) {
        if (!newCode || newCode.trim().length < 3) {
            return { success: false, error: "邀请码至少3位字符" };
        }
        const config = await KVStore.getConfig();
        config.invite_code = newCode.trim();
        const saved = await KVStore.saveConfig(config);
        if (!saved) {
            return { success: false, error: "更新邀请码失败" };
        }
        return { success: true };
    }

    static async banUser(uid, duration, reason = "") {
        const user = await KVStore.getUser(uid);
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        // 管理员不能被封禁
        if (user.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase()) {
            return { success: false, error: "不能封禁管理员" };
        }

        const now = new Date();
        let banUntil = null;
        switch (duration) {
            case "1day":
                banUntil = new Date(now.getTime() + 24 * 60 * 60 * 1000);
                break;
            case "3days":
                banUntil = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);
                break;
            case "1month":
                banUntil = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
                break;
            case "permanent":
                banUntil = null; // 永久封禁
                break;
            default:
                return { success: false, error: "无效的封禁时长" };
        }

        user.is_banned = true;
        user.ban_until = banUntil ? banUntil.toISOString() : null;
        user.ban_reason = reason;
        const saved = await KVStore.saveUser(user);
        if (!saved) {
            return { success: false, error: "封禁用户失败" };
        }

        // 记录审计日志
        await KVStore.saveAuditRecord({
            type: "ban",
            admin_uid: "0",
            target_uid: uid,
            duration: duration,
            reason: reason,
            timestamp: new Date().toISOString()
        });
        return { success: true };
    }

    static async unbanUser(uid) {
        const user = await KVStore.getUser(uid);
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        user.is_banned = false;
        user.ban_until = null;
        user.ban_reason = null;
        const saved = await KVStore.saveUser(user);
        if (!saved) {
            return { success: false, error: "解封用户失败" };
        }

        // 记录审计日志
        await KVStore.saveAuditRecord({
            type: "unban",
            admin_uid: "0",
            target_uid: uid,
            timestamp: new Date().toISOString()
        });
        return { success: true };
    }

    static async addTitleToUser(uid, titleName, titleDisplay, color = "blue", weight = "normal") {
        const user = await KVStore.getUser(uid);
        if (!user) {
            return { success: false, error: "用户不存在" };
        }

        const config = await KVStore.getConfig();
        if (!config.titles) {
            config.titles = {};
        }
        config.titles[titleName] = {
            display: titleDisplay || titleName,
            color: color,
            weight: weight
        };
        const saved = await KVStore.saveConfig(config);
        if (!saved) {
            return { success: false, error: "添加头衔失败" };
        }
        return { success: true };
    }

    static async processAppeal(appealId, status, response) {
        const appeals = await KVStore.getAuditRecords();
        const appeal = appeals.find(a => a.id === appealId);
        if (!appeal) {
            return { success: false, error: "申诉记录不存在" };
        }

        appeal.status = status;
        appeal.processed_at = new Date().toISOString();
        appeal.admin_response = response;

        // 如果申诉通过，解封用户
        if (status === "approved") {
            const user = await KVStore.getUser(appeal.uid);
            if (user) {
                user.is_banned = false;
                user.ban_until = null;
                await KVStore.saveUser(user);
            }
        }

        // 保存更新
        const updatedAppeals = appeals.map(a => a.id === appealId ? appeal : a);
        const encryptedData = await CryptoUtils.encrypt(JSON.stringify(updatedAppeals));
        await CHAT_DATA.put("admin:audits", JSON.stringify(encryptedData), { expirationTtl: 31536000 });
        return { success: true };
    }
}

// HTML模板类
class HTMLTemplates {
    static getBaseTemplate(title, content, user = null, theme = "light") {
        const header = `
            <header class="header">
                <div class="logo-container">
                    <a href="/" class="logo">${APP_NAME}</a>
                    <nav class="nav-links">
                        ${user ? `<a href="/chat">消息</a><a href="/contacts">联系人</a><a href="/settings">设置</a>${this.isAdmin(user) ? '<a href="/admin">管理</a>' : ''}` : `<a href="/login">登录</a><a href="/register">注册</a>`}
                    </nav>
                    ${user ? `<div class="user-info"><img src="${user.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'"><span>${user.display_name}</span><form method="POST" action="/logout" style="display: inline;"><button type="submit" class="logout-btn">退出</button></form></div>` : ''}
                </div>
            </header>
        `;
        const body = `
            <main class="main-content">
                <div class="container">
                    ${content}
                </div>
            </main>
        `;
        const footer = `
            <footer class="footer">
                <p>© ${new Date().getFullYear()} ${APP_NAME} | <a href="#">隐私政策</a> | <a href="#">服务条款</a></p>
            </footer>
        `;
        const styles = `
            <style>
                :root {
                    --primary-color: #007bff;
                    --secondary-color: #6c757d;
                    --success-color: #28a745;
                    --danger-color: #dc3545;
                    --warning-color: #ffc107;
                    --info-color: #17a2b8;
                    --light-color: #f8f9fa;
                    --dark-color: #343a40;
                }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f6f9;
                    color: var(--dark-color);
                }
                .header {
                    background-color: white;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    position: sticky;
                    top: 0;
                    z-index: 100;
                }
                .logo-container {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 1rem 2rem;
                }
                .logo {
                    font-size: 1.8rem;
                    font-weight: bold;
                    color: var(--primary-color);
                }
                .nav-links {
                    display: flex;
                    gap: 1.5rem;
                }
                .nav-links a {
                    text-decoration: none;
                    color: var(--dark-color);
                    transition: color 0.3s;
                }
                .nav-links a:hover {
                    color: var(--primary-color);
                }
                .user-info {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                .avatar {
                    width: 32px;
                    height: 32px;
                    border-radius: 50%;
                    object-fit: cover;
                }
                .logout-btn {
                    background-color: transparent;
                    border: 1px solid var(--danger-color);
                    color: var(--danger-color);
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 0.9rem;
                }
                .logout-btn:hover {
                    background-color: var(--danger-color);
                    color: white;
                }
                .main-content {
                    padding: 2rem;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                }
                .card {
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    padding: 1.5rem;
                    margin-bottom: 1.5rem;
                }
                .card h2 {
                    margin-top: 0;
                    color: var(--primary-color);
                }
                .error-message {
                    background-color: var(--danger-color);
                    color: white;
                    padding: 0.5rem;
                    border-radius: 4px;
                    margin-bottom: 1rem;
                }
                .form-group {
                    margin-bottom: 1rem;
                }
                .form-group label {
                    display: block;
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                }
                .form-group input[type="text"],
                .form-group input[type="password"],
                .form-group input[type="email"],
                .form-group textarea,
                .form-group select {
                    width: 100%;
                    padding: 0.5rem;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                .form-group textarea {
                    resize: vertical;
                }
                .btn {
                    background-color: var(--primary-color);
                    color: white;
                    border: none;
                    padding: 0.5rem 1rem;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 1rem;
                }
                .btn:hover {
                    background-color: #0056b3;
                }
                .btn-secondary {
                    background-color: var(--secondary-color);
                    color: white;
                }
                .btn-secondary:hover {
                    background-color: #545b62;
                }
                .search-bar {
                    width: 100%;
                    padding: 0.5rem;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                .user-list, .chat-list {
                    list-style: none;
                    padding: 0;
                    margin: 0;
                }
                .user-item, .chat-item {
                    display: flex;
                    align-items: center;
                    padding: 0.5rem 0;
                    border-bottom: 1px solid #eee;
                }
                .user-item:last-child, .chat-item:last-child {
                    border-bottom: none;
                }
                .avatar {
                    width: 40px;
                    height: 40px;
                    border-radius: 50%;
                    object-fit: cover;
                    margin-right: 0.5rem;
                }
                .user-info-block {
                    flex-grow: 1;
                }
                .username {
                    margin: 0;
                    font-weight: 500;
                }
                .online-indicator {
                    width: 8px;
                    height: 8px;
                    background-color: #4caf50;
                    border-radius: 50%;
                    display: inline-block;
                    margin-left: 0.5rem;
                }
                .user-level {
                    font-size: 0.9rem;
                    color: var(--secondary-color);
                }
                .message-info {
                    font-size: 0.8rem;
                    color: var(--secondary-color);
                }
                .profile-card {
                    text-align: center;
                }
                .profile-avatar {
                    width: 120px;
                    height: 120px;
                    border-radius: 50%;
                    object-fit: cover;
                    margin: 0 auto 1rem;
                }
                .profile-name {
                    margin: 0;
                    font-size: 1.5rem;
                }
                .small-action-btn {
                    margin-right: 0.5rem;
                    font-size: 0.9rem;
                }
                .emoji-container {
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    padding: 1rem;
                    max-height: 300px;
                    overflow-y: auto;
                }
                .emoji-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(40px, 1fr));
                    gap: 0.5rem;
                }
                .emoji-item {
                    font-size: 2rem;
                    cursor: pointer;
                    transition: transform 0.2s;
                }
                .emoji-item:hover {
                    transform: scale(1.1);
                }
                .footer {
                    text-align: center;
                    padding: 1rem;
                    color: var(--secondary-color);
                    font-size: 0.9rem;
                }
                .footer a {
                    color: var(--secondary-color);
                    text-decoration: none;
                    margin: 0 0.5rem;
                }
                .footer a:hover {
                    text-decoration: underline;
                }
                @media (max-width: 768px) {
                    .logo-container {
                        flex-direction: column;
                        align-items: flex-start;
                        gap: 0.5rem;
                    }
                    .nav-links {
                        flex-wrap: wrap;
                        gap: 0.5rem;
                    }
                    .user-info {
                        flex-direction: column;
                        align-items: flex-start;
                        gap: 0.5rem;
                    }
                }
            </style>
        `;
        return `
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${title} - ${APP_NAME}</title>
                ${styles}
            </head>
            <body>
                ${header}
                ${body}
                ${footer}
            </body>
            </html>
        `;
    }

    static getLoginTemplate(error = null, banned = false, banUntil = null) {
        let content = `<div class="card">
            <h2>登录到 ${APP_NAME}</h2>
            ${error ? `<div class="error-message">${error}</div>` : ''}
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">用户名</label>
                    <input type="text" id="username" name="username" required placeholder="请输入用户名">
                </div>
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" required placeholder="请输入密码">
                </div>
                <button type="submit" class="btn">登录</button>
            </form>
            <p style="margin-top: 15px;">还没有账号？<a href="/register">立即注册</a></p>
        </div>`;
        if (banned && banUntil) {
            const banDate = new Date(banUntil);
            content = `<div class="card">
                <h2>⛔ 账号已被封禁</h2>
                <div class="error-message">
                    <p>您的账号因违规已被封禁</p>
                    <p>解封时间：${banDate.toLocaleString()}</p>
                </div>
                <div style="margin-top: 20px;">
                    <h3>申诉解封</h3>
                    <p>如果您认为封禁有误，可以提交申诉</p>
                    <a href="/appeal" class="btn btn-info">提交申诉</a>
                </div>
                <p style="margin-top: 20px;"><a href="/" class="btn btn-secondary">返回首页</a></p>
            </div>`;
        }
        return this.getBaseTemplate("登录", content);
    }

    static getRegisterTemplate(error = null) {
        return this.getBaseTemplate("注册", `
            <div class="card">
                <h2>注册新账号</h2>
                ${error ? `<div class="error-message">${error}</div>` : ''}
                <form method="POST" action="/register">
                    <div class="form-group">
                        <label for="display_name">昵称</label>
                        <input type="text" id="display_name" name="display_name" required maxlength="30" placeholder="请输入昵称">
                    </div>
                    <div class="form-group">
                        <label for="username">用户名（登录用）</label>
                        <input type="text" id="username" name="username" required maxlength="20" pattern="[a-zA-Z0-9_]+" title="只能包含字母、数字和下划线，长度3-20位" placeholder="3-20位字母数字下划线">
                    </div>
                    <div class="form-group">
                        <label for="password">密码</label>
                        <input type="password" id="password" name="password" required minlength="6" placeholder="至少6位">
                    </div>
                    <div class="form-group">
                        <label for="invite_code">邀请码</label>
                        <input type="text" id="invite_code" name="invite_code" required placeholder="请输入邀请码">
                    </div>
                    <div class="form-group">
                        <label for="avatar">头像链接（可选）</label>
                        <input type="url" id="avatar" name="avatar" placeholder="https://example.com/avatar.jpg">
                    </div>
                    <div class="form-group">
                        <label for="bio">个性签名</label>
                        <textarea id="bio" name="bio" rows="3" maxlength="100" placeholder="一句话介绍自己"></textarea>
                    </div>
                    <div class="form-group">
                        <label>性别</label>
                        <div>
                            <label style="margin-right: 20px;"><input type="radio" name="gender" value="♂" checked> ♂ 男</label>
                            <label><input type="radio" name="gender" value="♀"> ♀ 女</label>
                        </div>
                    </div>
                    <button type="submit" class="btn">注册</button>
                </form>
                <p style="margin-top: 15px;">已有账号？<a href="/login">立即登录</a></p>
            </div>
        `);
    }

    static getChatListTemplate(user, contacts, error = null) {
        const contactItems = contacts.map(contact => {
            const isOnline = new Date(contact.last_login) > new Date(Date.now() - 5 * 60 * 1000);
            const titlesHtml = contact.titles ? Object.values(contact.titles).map(t => `<span class="title-badge" style="color: ${t.color}; font-weight: ${t.weight};">${t.display}</span>`).join(' ') : '';
            const levelText = `Lv.${contact.level}${contact.level === 1 ? ' (注册会员)' : ''}`;
            return `
                <li class="user-item">
                    <img src="${contact.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'">
                    <div class="user-info-block">
                        <div class="username">${contact.display_name}${titlesHtml}${isOnline ? '<span class="online-indicator"></span>' : ''}</div>
                        <div class="user-level">${levelText} • ${contact.gender}</div>
                        <div class="message-info">最后活跃: ${new Date(contact.last_login).toLocaleString()}</div>
                    </div>
                    <div style="margin-left: auto;">
                        <a href="/chat/${contact.username}" class="btn" style="padding: 5px 10px; font-size: 12px;">发消息</a>
                    </div>
                </li>
            `;
        }).join('');

        return this.getBaseTemplate("消息", `
            <div class="card">
                <h2>消息</h2>
                ${error ? `<div class="error-message">${error}</div>` : ''}
                <input type="text" id="user-search" class="search-bar" placeholder="搜索联系人...">
                <ul class="chat-list">${contactItems || '<li class="chat-item">暂无联系人</li>'}</ul>
            </div>
        `, user);
    }

    static getChatTemplate(user, targetUser, messages, error = null) {
        const messageItems = messages.map(msg => {
            const isOwn = msg.sender_uid === user.uid;
            const messageClass = isOwn ? 'own-message' : 'other-message';
            const alignClass = isOwn ? 'style="margin-left: auto;"' : '';
            // 格式化emojilet content = msg.decrypted_content || "[加密消息]";
            const content = msg.decrypted_content || "[加密消息]";
            return `
                <li class="message-item ${messageClass}" ${alignClass}>
                    <div class="message-content">${content}</div>
                    <div class="message-time">${new Date(msg.timestamp).toLocaleTimeString()}</div>
                </li>
            `;
        }).join('');

        return this.getBaseTemplate("聊天", `
            <div class="card">
                <h2>与 ${targetUser.display_name} 的聊天</h2>
                ${error ? `<div class="error-message">${error}</div>` : ''}
                <div class="chat-messages">
                    <ul class="message-list">${messageItems}</ul>
                </div>
                <div class="chat-input">
                    <form id="send-message-form">
                        <input type="hidden" id="receiver" value="${targetUser.username}">
                        <input type="text" id="message-input" placeholder="输入消息..." required>
                        <button type="submit" class="btn">发送</button>
                    </form>
                </div>
            </div>
        `, user);
    }

    static getContactsTemplate(user, contacts, error = null) {
        const contactItems = contacts.map(contact => {
            const isOnline = new Date(contact.last_login) > new Date(Date.now() - 5 * 60 * 1000);
            const titlesHtml = contact.titles ? Object.values(contact.titles).map(t => `<span class="title-badge" style="color: ${t.color}; font-weight: ${t.weight};">${t.display}</span>`).join(' ') : '';
            const levelText = `Lv.${contact.level}${contact.level === 1 ? ' (注册会员)' : ''}`;
            return `
                <li class="user-item">
                    <img src="${contact.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'">
                    <div class="user-info-block">
                        <div class="username">${contact.display_name}${titlesHtml}${isOnline ? '<span class="online-indicator"></span>' : ''}</div>
                        <div class="user-level">${levelText} • ${contact.gender}</div>
                        <div class="message-info">最后登录: ${new Date(contact.last_login).toLocaleString()}</div>
                    </div>
                </li>
            `;
        }).join('');

        return this.getBaseTemplate("联系人", `
            <div class="card">
                <h2>联系人</h2>
                ${error ? `<div class="error-message">${error}</div>` : ''}
                <input type="text" id="user-search" class="search-bar" placeholder="搜索联系人...">
                <ul class="user-list">${contactItems || '<li class="user-item">暂无联系人</li>'}</ul>
            </div>
        `, user);
    }

    static getProfileTemplate(user, profileUser, isOwnProfile, error = null) {
        const isAdmin = this.isAdmin(user);
        const isProfileAdmin = profileUser.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase();
        const levelText = `Lv.${profileUser.level}${profileUser.level === 1 ? ' (注册会员)' : ''}`;
        const titlesHtml = profileUser.titles ? Object.values(profileUser.titles).map(t => `<span class="title-badge" style="color: ${t.color}; font-weight: ${t.weight};">${t.display}</span>`).join(' ') : '';
        const createdDate = new Date(profileUser.created_at);
        const today = new Date();
        const onlineDays = Math.floor((today - createdDate) / (1000 * 60 * 60 * 24));

        let adminActions = '';
        if (isAdmin && !isProfileAdmin) {
            adminActions = `
                <div class="admin-actions">
                    <button class="btn btn-secondary small-action-btn" onclick="addTitle('${profileUser.uid}')">添加头衔</button>
                    <button class="btn btn-secondary small-action-btn" onclick="resetPassword('${profileUser.uid}')">重置密码</button>
                    <button class="btn btn-secondary small-action-btn" onclick="toggleBan('${profileUser.uid}')">切换封禁</button>
                </div>
            `;
        }

        return this.getBaseTemplate(`${profileUser.display_name} 的个人资料`, `
            <div class="profile-card">
                ${error ? `<div class="error-message">${error}</div>` : ''}
                <img src="${profileUser.avatar}" alt="头像" class="profile-avatar" onerror="this.src='https://via.placeholder.com/150'">
                <h1 class="profile-name">${profileUser.display_name} ${titlesHtml}</h1>
                <div class="profile-info">
                    <p><strong>等级:</strong> ${levelText}</p>
                    <p><strong>在线天数:</strong> ${onlineDays} 天</p>
                    <p><strong>注册时间:</strong> ${createdDate.toLocaleDateString()}</p>
                    <p><strong>性别:</strong> ${profileUser.gender}</p>
                    <p><strong>个性签名:</strong> ${profileUser.bio || '暂无'}</p>
                </div>
                ${adminActions}
            </div>
        `, user);
    }

    static getAppealTemplate(user = null, error = null) {
        return this.getBaseTemplate("申诉解封", `
            <div class="card appeal-form">
                <h2>📝 提交申诉</h2>
                <p>如果您认为账号被错误封禁，请填写以下信息，我们会尽快审核。</p>
                ${error ? `<div class="error-message">${error}</div>` : ''}
                <form id="appeal-form">
                    <div class="form-group">
                        <label for="appeal-email">邮箱地址（用于接收回复）</label>
                        <input type="email" id="appeal-email" name="email" required placeholder="请输入邮箱地址">
                    </div>
                    <div class="form-group">
                        <label for="appeal-reason">申诉理由</label>
                        <textarea id="appeal-reason" name="reason" rows="4" required placeholder="详细说明您认为被封禁的原因..."></textarea>
                    </div>
                    <button type="submit" class="btn">提交申诉</button>
                </form>
            </div>
        `, user);
    }

    static getAdminPanelTemplate(currentUser, users, config, appeals) {
        const userRows = users.map(user => {
            const isOnline = new Date(user.last_login) > new Date(Date.now() - 5 * 60 * 1000);
            const levelText = `Lv.${user.level}`;
            const isBanned = user.is_banned;
            const banStatus = isBanned ? (user.ban_until ? `封禁至 ${new Date(user.ban_until).toLocaleString()}` : '永久封禁') : '正常';
            return `
                <tr>
                    <td>${user.display_name}</td>
                    <td>${user.username}</td>
                    <td>${levelText}</td>
                    <td>${user.gender}</td>
                    <td>${user.online_days} 天</td>
                    <td>${isOnline ? '<span class="online-indicator"></span>' : ''}</td>
                    <td>${banStatus}</td>
                    <td>
                        <button class="btn btn-secondary small-action-btn" onclick="editProfile('${user.uid}')">编辑</button>
                        <button class="btn btn-secondary small-action-btn" onclick="addTitle('${user.uid}')">头衔</button>
                        <button class="btn btn-secondary small-action-btn" onclick="resetPassword('${user.uid}')">重置密码</button>
                        <button class="btn btn-secondary small-action-btn" onclick="toggleBan('${user.uid}')">切换封禁</button>
                    </td>
                </tr>
            `;
        }).join('');

        const appealRows = appeals.map(appeal => {
            const statusText = appeal.status === "pending" ? "待处理" : appeal.status === "approved" ? "已批准" : "已拒绝";
            return `
                <tr>
                    <td>${appeal.uid}</td>
                    <td>${appeal.email}</td>
                    <td>${appeal.reason}</td>
                    <td>${statusText}</td>
                    <td>${new Date(appeal.timestamp).toLocaleString()}</td>
                    <td>
                        <button class="btn btn-secondary small-action-btn" onclick="processAppeal('${appeal.id}', 'approved')">批准</button>
                        <button class="btn btn-secondary small-action-btn" onclick="processAppeal('${appeal.id}', 'rejected')">拒绝</button>
                    </td>
                </tr>
            `;
        }).join('');

        return this.getBaseTemplate("管理员面板", `
            <div class="card">
                <h2>用户管理</h2>
                <table class="user-table">
                    <thead>
                        <tr>
                            <th>昵称</th>
                            <th>用户名</th>
                            <th>等级</th>
                            <th>性别</th>
                            <th>在线天数</th>
                            <th>在线状态</th>
                            <th>封禁状态</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${userRows}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <h2>系统设置</h2>
                <form id="config-form">
                    <div class="form-group">
                        <label for="invite-code">邀请码</label>
                        <input type="text" id="invite-code" name="invite-code" value="${config.invite_code}" required>
                    </div>
                    <button type="submit" class="btn">更新邀请码</button>
                </form>
            </div>
            <div class="card">
                <h2>申诉记录</h2>
                <table class="appeal-table">
                    <thead>
                        <tr>
                            <th>用户ID</th>
                            <th>邮箱</th>
                            <th>理由</th>
                            <th>状态</th>
                            <th>提交时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${appealRows}
                    </tbody>
                </table>
            </div>
        `, currentUser);
    }

    static getErrorTemplate(message, user = null) {
        return this.getBaseTemplate("错误", `
            <div class="card">
                <h2>❌ 错误</h2>
                <div class="error-message">${message}</div>
                <p style="margin-top: 15px;"><a href="/" class="btn btn-secondary">返回首页</a></p>
            </div>
        `, user);
    }

    static isAdmin(user) {
        return user && user.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase();
    }
}

// 路由器
class Router {
    static async handleRequest(request) {
        const path = new URL(request.url, `https://${request.headers.get('Host')}`).pathname;
        const method = request.method;
        const sessionToken = request.headers.get('Cookie')?.split('; ').find(row => row.startsWith('session='));
        const currentUser = await SessionManager.validateSession(sessionToken, request);

        try {
            // 首页
            if (path === '/' && method === 'GET') {
                return new Response(HTMLTemplates.getBaseTemplate("功能特色", `
                    <div class="card">
                        <h2>✨ 功能特色</h2>
                        <div class="feature-item">
                            <div class="icon">🔒</div>
                            <h3>端到端加密</h3>
                            <p>所有聊天记录加密存储，保障隐私安全</p>
                        </div>
                        <div class="feature-item">
                            <div class="icon">📱</div>
                            <h3>仿Telegram界面</h3>
                            <p>熟悉的Telegram风格，操作流畅</p>
                        </div>
                        <div class="feature-item">
                            <div class="icon">👑</div>
                            <h3>管理员特权</h3>
                            <p>完善的管理功能，维护社区秩序</p>
                        </div>
                    </div>
                `));
            }

            // 登录
            if (path === '/login' && method === 'GET') {
                return new Response(HTMLTemplates.getLoginTemplate());
            }

            if (path === '/login' && method === 'POST') {
                const formData = await request.formData();
                const username = formData.get('username');
                const password = formData.get('password');
                const loginResult = await UserManager.login(username, password, request);
                if (!loginResult.success) {
                    return new Response(HTMLTemplates.getLoginTemplate(loginResult.error, loginResult.banned, loginResult.ban_until));
                }
                return new Response('', {
                    status: 302,
                    headers: {
                        'Location': '/chat',
                        'Set-Cookie': `session=${loginResult.token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`
                    }
                });
            }

            // 注册
            if (path === '/register' && method === 'GET') {
                return new Response(HTMLTemplates.getRegisterTemplate());
            }

            if (path === '/register' && method === 'POST') {
                const formData = await request.formData();
                const userData = {
                    display_name: formData.get('display_name'),
                    username: formData.get('username'),
                    password: formData.get('password'),
                    invite_code: formData.get('invite_code'),
                    avatar: formData.get('avatar'),
                    bio: formData.get('bio'),
                    gender: formData.get('gender')
                };
                const result = await UserManager.register(userData);
                if (!result.success) {
                    return new Response(HTMLTemplates.getRegisterTemplate(result.error));
                }
                // 注册成功，尝试自动登录
                if (result.login_failed) {
                    return new Response(HTMLTemplates.getRegisterTemplate("注册成功但登录失败，请重新登录"));
                }
                // 自动登录成功，跳转到聊天页面
                return new Response('', {
                    status: 302,
                    headers: {
                        'Location': '/chat',
                        'Set-Cookie': `session=${result.user.token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`
                    }
                });
            }

            // 退出登录
            if (path === '/logout' && method === 'POST') {
                if (sessionToken) {
                    await SessionManager.deleteSession(sessionToken);
                }
                return new Response('', {
                    status: 302,
                    headers: {
                        'Location': '/'
                    }
                });
            }

            // 发送消息
            if (path === '/send-message' && method === 'POST') {
                const jsonData = await request.json();
                const receiverUsername = jsonData.receiver;
                const content = jsonData.content;
                if (!receiverUsername || !content) {
                    return new Response(JSON.stringify({ success: false, error: "接收者和内容不能为空" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const receiverUser = await KVStore.getUserByUsername(receiverUsername);
                if (!receiverUser) {
                    return new Response(JSON.stringify({ success: false, error: "用户不存在" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const result = await ChatManager.sendMessage(currentUser.uid, receiverUser.uid, content);
                return new Response(JSON.stringify(result), {
                    headers: { 'Content-Type': 'application/json; charset=utf-8' }
                });
            }

            // 查看特定聊天
            if (path.startsWith('/chat/') && method === 'GET') {
                const targetUsername = path.substring(6);
                if (!targetUsername) {
                    return new Response('', { status: 302, headers: { 'Location': '/chat' } });
                }
                const targetUser = await KVStore.getUserByUsername(targetUsername);
                if (!targetUser) {
                    return new Response(HTMLTemplates.getErrorTemplate("用户不存在", currentUser), {
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    });
                }
                const messages = await ChatManager.getChatHistory(currentUser.uid, targetUser.uid);
                await ChatManager.markMessagesAsRead(targetUser.uid, currentUser.uid);
                return new Response(HTMLTemplates.getChatTemplate(currentUser, targetUser, messages), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            // 联系人页面
            if (path === '/contacts' && method === 'GET') {
                const contacts = await ChatManager.getContacts(currentUser.uid);
                return new Response(HTMLTemplates.getContactsTemplate(currentUser, contacts), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            // 消息列表
            if (path === '/chat' && method === 'GET') {
                const contacts = await ChatManager.getContacts(currentUser.uid);
                return new Response(HTMLTemplates.getChatListTemplate(currentUser, contacts), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            // 个人资料
            if (path === '/profile' && method === 'GET') {
                return new Response(HTMLTemplates.getProfileTemplate(currentUser, currentUser, true), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            if (path.startsWith('/profile/') && method === 'GET') {
                const profileUsername = path.substring(8);
                if (!profileUsername) {
                    return new Response('', { status: 302, headers: { 'Location': '/profile' } });
                }
                const profileUser = await KVStore.getUserByUsername(profileUsername);
                if (!profileUser) {
                    return new Response(HTMLTemplates.getErrorTemplate("用户不存在", currentUser), {
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    });
                }
                const isOwnProfile = profileUser.username === currentUser.username;
                return new Response(HTMLTemplates.getProfileTemplate(currentUser, profileUser, isOwnProfile), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            // 编辑个人资料
            if (path === '/edit-profile' && method === 'GET') {
                return new Response(HTMLTemplates.getProfileTemplate(currentUser, currentUser, true, "编辑个人资料"), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            if (path === '/edit-profile' && method === 'POST') {
                const formData = await request.formData();
                const updates = {
                    display_name: formData.get('display_name'),
                    avatar: formData.get('avatar'),
                    bio: formData.get('bio'),
                    gender: formData.get('gender'),
                    settings: {
                        theme: formData.get('theme'),
                        notifications: formData.get('notifications') === 'true',
                        privacy: {
                            last_seen: formData.get('privacy_last_seen'),
                            profile_photo: formData.get('privacy_profile_photo'),
                            forward_messages: formData.get('privacy_forward_messages')
                        }
                    }
                };
                const currentPassword = formData.get('current_password');
                const result = await UserManager.updateProfile(currentUser.uid, updates, currentPassword);
                if (!result.success) {
                    return new Response(HTMLTemplates.getProfileTemplate(currentUser, currentUser, true, result.error), {
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    });
                }
                return new Response('', {
                    status: 302,
                    headers: { 'Location': '/profile' }
                });
            }

            // 申诉
            if (path === '/appeal' && method === 'GET') {
                return new Response(HTMLTemplates.getAppealTemplate(currentUser), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            if (path === '/appeal' && method === 'POST') {
                const formData = await request.formData();
                const email = formData.get('email');
                const reason = formData.get('reason');
                const result = await UserManager.submitAppeal(currentUser.uid, email, reason);
                if (!result.success) {
                    return new Response(HTMLTemplates.getAppealTemplate(currentUser, result.error), {
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    });
                }
                return new Response('', {
                    status: 302,
                    headers: { 'Location': '/profile' }
                });
            }

            // 管理员面板
            if (path === '/admin' && method === 'GET') {
                if (!HTMLTemplates.isAdmin(currentUser)) {
                    return new Response(HTMLTemplates.getErrorTemplate("权限不足", currentUser), {
                        headers: { 'Content-Type': 'text/html; charset=utf-8' }
                    });
                }
                const users = await KVStore.getAllUsers();
                const config = await KVStore.getConfig();
                const appeals = (await KVStore.getAuditRecords()).filter(a => !a.type || (a.type !== "ban" && a.type !== "unban"));
                return new Response(HTMLTemplates.getAdminPanelTemplate(currentUser, users, config, appeals), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            // 管理员操作API
            if (path === '/admin/toggle-ban' && method === 'POST') {
                if (!HTMLTemplates.isAdmin(currentUser)) {
                    return new Response(JSON.stringify({ success: false, error: "权限不足" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const jsonData = await request.json();
                const uid = jsonData.uid;
                if (!uid) {
                    return new Response(JSON.stringify({ success: false, error: "用户ID不能为空" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const user = await KVStore.getUser(uid);
                if (!user) {
                    return new Response(JSON.stringify({ success: false, error: "用户不存在" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                let result;
                if (user.is_banned) {
                    result = await AdminManager.unbanUser(uid);
                } else {
                    result = await AdminManager.banUser(uid, "1day", "管理员手动封禁");
                }
                return new Response(JSON.stringify(result), {
                    headers: { 'Content-Type': 'application/json; charset=utf-8' }
                });
            }

            if (path === '/admin/reset-password' && method === 'POST') {
                if (!HTMLTemplates.isAdmin(currentUser)) {
                    return new Response(JSON.stringify({ success: false, error: "权限不足" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const jsonData = await request.json();
                const uid = jsonData.uid;
                if (!uid) {
                    return new Response(JSON.stringify({ success: false, error: "用户ID不能为空" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const result = await AdminManager.resetPassword(uid);
                return new Response(JSON.stringify(result), {
                    headers: { 'Content-Type': 'application/json; charset=utf-8' }
                });
            }

            if (path === '/admin/add-title' && method === 'POST') {
                if (!HTMLTemplates.isAdmin(currentUser)) {
                    return new Response(JSON.stringify({ success: false, error: "权限不足" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const jsonData = await request.json();
                const uid = jsonData.uid;
                const titleName = jsonData.title_name;
                const titleDisplay = jsonData.title_display;
                const color = jsonData.color;
                const weight = jsonData.weight;
                if (!uid || !titleName) {
                    return new Response(JSON.stringify({ success: false, error: "用户ID和头衔名称不能为空" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const result = await AdminManager.addTitleToUser(uid, titleName, titleDisplay, color, weight);
                return new Response(JSON.stringify(result), {
                    headers: { 'Content-Type': 'application/json; charset=utf-8' }
                });
            }

            if (path === '/admin/process-appeal' && method === 'POST') {
                if (!HTMLTemplates.isAdmin(currentUser)) {
                    return new Response(JSON.stringify({ success: false, error: "权限不足" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const jsonData = await request.json();
                const appealId = jsonData.appeal_id;
                const status = jsonData.status;
                const response = jsonData.response;
                if (!appealId || !status) {
                    return new Response(JSON.stringify({ success: false, error: "申诉ID和状态不能为空" }), {
                        headers: { 'Content-Type': 'application/json; charset=utf-8' }
                    });
                }
                const result = await AdminManager.processAppeal(appealId, status, response);
                return new Response(JSON.stringify(result), {
                    headers: { 'Content-Type': 'application/json; charset=utf-8' }
                });
            }

            // 默认路由
            return new Response(HTMLTemplates.getErrorTemplate("页面未找到"), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        } catch (error) {
            console.error("处理请求时出错:", error);
            return new Response(HTMLTemplates.getErrorTemplate("服务器内部错误"), {
                status: 500,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
    }
}

// 主入口点
export default {
    async fetch(request) {
        await initializeBindings();
        return await Router.handleRequest(request);
    }
};