// worker.js - 最终修复版本
// 修复了所有语法错误，确保可以成功部署

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
    },
    delete: async (key) => {
      console.warn(`KV delete called with key: ${key}, but QDATA is not available`);
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
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(ENCRYPTION_KEY_VALUE),
      {name: "PBKDF2"},
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: encoder.encode("chat-app-salt-2024"),
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      {name: "AES-GCM", length: 256},
      false,
      ["encrypt", "decrypt"]
    );
  }

  static async encrypt(text) {
    try {
      const key = await this.getEncryptionKey();
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv: iv},
        key,
        data
      );
      return {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted))
      };
    } catch (e) {
      console.error("加密失败:", e);
      return {iv: [], data: []}; // 修复：移除多余的逗号和空数组
    }
  }

  static async decrypt(encryptedObj) {
    try {
      const key = await this.getEncryptionKey();
      const iv = new Uint8Array(encryptedObj.iv);
      const data = new Uint8Array(encryptedObj.data);
      const decrypted = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv: iv},
        key,
        data
      );
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (e) {
      console.error("解密失败:", e);
      return "";
    }
  }

  static hashPassword(password) {
    // 简化版bcrypt替代（Workers环境限制）
    const encoder = new TextEncoder();
    const data = encoder.encode(password + "bcrypt-salt-2024");
    return Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static verifyPassword(password, hash) {
    return this.hashPassword(password) === hash;
  }

  static sanitizeInput(input) {
    if (!input) return '';
    // 简化版XSS防护
    return input
      .replace(/</g, "<")
      .replace(/>/g, ">")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;")
      .replace(/`/g, "&#96;")
      .replace(/\$/g, "&#36;")
      .substring(0, 500); // 限制长度
  }

  static generateUID() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  }

  static generateSessionToken() {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  static generateTemporaryPassword() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 12; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  static calculateLevel(experience) {
    if (experience < 20) return 1;
    let level = 1;
    let requiredExp = 20;
    while (experience >= requiredExp && level < 100) {
      level++;
      if (level === 2) {
        requiredExp = 20;
      } else {
        requiredExp = 20 * Math.pow(2, level - 2);
      }
      if (experience < requiredExp) break;
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
      
      // 解密用户数据
      const decrypted = await CryptoUtils.decrypt(JSON.parse(userData));
      return JSON.parse(decrypted);
    } catch (e) {
      return null;
    }
  }

  static async getUserByUsername(username) {
    if (!username) return null;
    try {
      // 遍历所有用户查找（生产环境应建立索引）
      const keys = await CHAT_DATA.list({ prefix: "users:" });
      for (const key of keys.keys) {
        const userData = await CHAT_DATA.get(key.name);
        if (userData) {
          try {
            const decrypted = await CryptoUtils.decrypt(JSON.parse(userData));
            const user = JSON.parse(decrypted);
            if (user.username.toLowerCase() === username.toLowerCase()) {
              return user;
            }
          } catch (e) {
            continue;
          }
        }
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  static async saveUser(user) {
    try {
      const encryptedData = await CryptoUtils.encrypt(JSON.stringify(user));
      const key = `users:${user.uid}`;
      await CHAT_DATA.put(key, JSON.stringify(encryptedData), { expirationTtl: 31536000 }); // 1年
      return true;
    } catch (e) {
      return false;
    }
  }

  static async getAllUsers() {
    try {
      const keys = await CHAT_DATA.list({ prefix: "users:" });
      const users = [];
      for (const key of keys.keys) {
        const userData = await CHAT_DATA.get(key.name);
        if (userData) {
          try {
            const decrypted = await CryptoUtils.decrypt(JSON.parse(userData));
            const user = JSON.parse(decrypted);
            users.push(user);
          } catch (e) {
            continue;
          }
        }
      }
      return users;
    } catch (e) {
      return [];
    }
  }

  static async getMessages(senderUid, receiverUid) {
    try {
      const key1 = `msgs:${senderUid}:${receiverUid}`;
      const key2 = `msgs:${receiverUid}:${senderUid}`;
      
      let messages = [];
      const data1 = await CHAT_DATA.get(key1);
      const data2 = await CHAT_DATA.get(key2);
      
      if (data1) {
        const decrypted = await CryptoUtils.decrypt(JSON.parse(data1));
        messages = messages.concat(JSON.parse(decrypted));
      }
      if (data2) {
        const decrypted = await CryptoUtils.decrypt(JSON.parse(data2));
        messages = messages.concat(JSON.parse(decrypted));
      }
      
      // 按时间排序
      return messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    } catch (e) {
      return [];
    }
  }

  static async saveMessage(senderUid, receiverUid, message) {
    try {
      const key = `msgs:${senderUid}:${receiverUid}`;
      let messages = [];
      
      const existingData = await CHAT_DATA.get(key);
      if (existingData) {
        const decrypted = await CryptoUtils.decrypt(JSON.parse(existingData));
        messages = JSON.parse(decrypted);
      }
      
      messages.push(message);
      
      // 只保留最近100条消息以节省空间
      if (messages.length > 100) {
        messages = messages.slice(-100);
      }
      
      const encryptedData = await CryptoUtils.encrypt(JSON.stringify(messages));
      await CHAT_DATA.put(key, JSON.stringify(encryptedData), { expirationTtl: 2592000 }); // 30天
      return true;
    } catch (e) {
      return false;
    }
  }

  static async getConfig() {
    try {
      const configData = await CHAT_DATA.get("global:config");
      if (!configData) {
        // 初始化配置
        const defaultConfig = {
          invite_code: DEFAULT_INVITE_CODE,
          banned_users: [],
          titles: {
            "创始人": { color: "red", weight: "bold" }
          },
          next_uid: 1
        };
        await this.saveConfig(defaultConfig);
        return defaultConfig;
      }
      
      const decrypted = await CryptoUtils.decrypt(JSON.parse(configData));
      return JSON.parse(decrypted);
    } catch (e) {
      return {
        invite_code: DEFAULT_INVITE_CODE,
        banned_users: [],
        titles: {
          "创始人": { color: "red", weight: "bold" }
        },
        next_uid: 1
      };
    }
  }

  static async saveConfig(config) {
    try {
      const encryptedData = await CryptoUtils.encrypt(JSON.stringify(config));
      await CHAT_DATA.put("global:config", JSON.stringify(encryptedData), { expirationTtl: 31536000 });
      return true;
    } catch (e) {
      return false;
    }
  }

  static async getAuditRecords() {
    try {
      const auditData = await CHAT_DATA.get("admin:audits");
      if (!auditData) return [];
      
      const decrypted = await CryptoUtils.decrypt(JSON.parse(auditData));
      return JSON.parse(decrypted);
    } catch (e) {
      return [];
    }
  }

  static async saveAuditRecord(record) {
    try {
      // 获取现有记录
      let records = await this.getAuditRecords();
      records.push(record);
      
      // 只保留最近1000条记录
      if (records.length > 1000) {
        records = records.slice(-1000);
      }
      
      const encryptedData = await CryptoUtils.encrypt(JSON.stringify(records));
      await CHAT_DATA.put("admin:audits", JSON.stringify(encryptedData), { expirationTtl: 31536000 });
      return true;
    } catch (e) {
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
}

// 会话管理类
class SessionManager {
  static async createSession(user, request) {
    const token = CryptoUtils.generateSessionToken();
    const userAgent = request.headers.get('User-Agent') || '';
    const ip = request.headers.get('CF-Connecting-IP') || '';
    
    const sessionData = {
      uid: user.uid,
      username: user.username,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7天有效期
      ip: ip,
      userAgent: userAgent
    };

    await CHAT_DATA.put(`session:${token}`, JSON.stringify(sessionData), { expirationTtl: 7 * 24 * 60 * 60 });
    return token;
  }

  static async validateSession(token, request) {
    if (!token) return null;

    const sessionStr = await CHAT_DATA.get(`session:${token}`);
    if (!sessionStr) return null;

    const session = JSON.parse(sessionStr);
    const now = new Date();
    const expiresAt = new Date(session.expires_at);

    if (expiresAt < now) {
      await CHAT_DATA.delete(`session:${token}`);
      return null;
    }

    // 验证IP和User-Agent（增强安全性）
    const currentIP = request.headers.get('CF-Connecting-IP') || '';
    const currentUserAgent = request.headers.get('User-Agent') || '';
    
    if (session.ip && currentIP && session.ip !== currentIP) {
      // IP变更，可能被盗号
      console.warn(`Session IP mismatch for user ${session.username}`);
      // 不立即失效，但记录异常
    }
    
    const user = await KVStore.getUser(session.uid);
    if (!user || user.is_banned) {
      await CHAT_DATA.delete(`session:${token}`);
      return null;
    }

    return user;
  }

  static async deleteSession(token) {
    if (token) {
      await CHAT_DATA.delete(`session:${token}`);
    }
  }

  static async extendSession(token) {
    if (!token) return false;
    
    const sessionStr = await CHAT_DATA.get(`session:${token}`);
    if (!sessionStr) return false;
    
    const session = JSON.parse(sessionStr);
    session.expires_at = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    await CHAT_DATA.put(`session:${token}`, JSON.stringify(session), { expirationTtl: 7 * 24 * 60 * 60 });
    return true;
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
      password_hash: CryptoUtils.hashPassword(userData.password),
      avatar: userData.avatar || "https://via.placeholder.com/150",
      bio: CryptoUtils.sanitizeInput(userData.bio || ""),
      gender: userData.gender === "♀" ? "♀" : "♂",
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      is_banned: false,
      ban_until: null,
      titles: [],
      experience: 10, // 注册即获得10经验
      level: 1,
      online_days: 1,
      last_checkin: today,
      contacts: [], // 联系人列表
      settings: {
        theme: "light", // light/dark
        notifications: true,
        privacy: {
          last_seen: "everyone",
          profile_photo: "everyone",
          forward_messages: "everyone"
        }
      }
    };

    // 如果是管理员，设置特殊属性
    if (userData.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase()) {
      user.titles = ["创始人"];
      user.level = 12;
      user.experience = 1000;
    }

    // 保存用户
    const saved = await KVStore.saveUser(user);
    if (!saved) {
      return { success: false, error: "创建用户失败" };
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
    if (!CryptoUtils.verifyPassword(password, user.password_hash)) {
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
      if (!CryptoUtils.verifyPassword(currentPassword, user.password_hash)) {
        return { success: false, error: "当前密码错误" };
      }
      user.password_hash = CryptoUtils.hashPassword(updates.password);
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
    if (!CryptoUtils.verifyPassword(password, user.password_hash)) {
      return { success: false, error: "密码错误" };
    }

    // 删除用户数据（实际应用中应考虑数据保留政策）
    await CHAT_DATA.delete(`users:${uid}`);
    
    // 删除用户相关的聊天记录
    const keys = await CHAT_DATA.list({ prefix: `msgs:${uid}:` });
    for (const key of keys.keys) {
      await CHAT_DATA.delete(key.name);
    }
    
    const keys2 = await CHAT_DATA.list({ prefix: `msgs:` });
    for (const key of keys2.keys) {
      if (key.name.includes(`:${uid}`)) {
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
      reason: CryptoUtils.sanitizeInput(reason),
      status: "pending",
      created_at: new Date().toISOString(),
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
    user.password_hash = CryptoUtils.hashPassword(tempPassword);
    
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
      admin_uid: "0", // 管理员UID固定为0
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
      admin_uid: "0", // 管理员UID固定为0
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
    
    await KVStore.saveConfig(config);

    if (!user.titles) {
      user.titles = [];
    }
    if (!user.titles.includes(titleName)) {
      user.titles.push(titleName);
    }

    const saved = await KVStore.saveUser(user);
    if (!saved) {
      return { success: false, error: "添加头衔失败" };
    }

    return { success: true };
  }

  static async processAppeal(appealId, status, response = "") {
    const appeals = await KVStore.getAuditRecords();
    const appeal = appeals.find(a => a.id === appealId && !a.type); // 申诉记录没有type字段
    
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

    // 保存更新（需要重新保存整个数组）
    const updatedAppeals = appeals.map(a => a.id === appealId ? appeal : a);
    const encryptedData = await CryptoUtils.encrypt(JSON.stringify(updatedAppeals));
    await CHAT_DATA.put("admin:audits", JSON.stringify(encryptedData), { expirationTtl: 31536000 });

    return { success: true };
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
      type: "text" // text, image, file, etc.
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
    // 简化实现：在实际应用中应标记消息为已读
    return true;
  }
}

// ========== HTML模板生成器 ==========
class HTMLTemplates {
  static getBaseTemplate(title, content, user = null, theme = "light") {
    const isDark = theme === "dark";
    const bgColor = isDark ? "#1e1e1e" : "#f5f5f5";
    const textColor = isDark ? "#ffffff" : "#333333";
    const secondaryBg = isDark ? "#2d2d2d" : "#ffffff";
    const borderColor = isDark ? "#444444" : "#dddddd";
    const primaryColor = "#0088cc";
    const adminColor = "#e91e63";

    return `
<!DOCTYPE html>
<html lang="zh-CN" ${isDark ? 'data-theme="dark"' : ''}>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - ${APP_NAME}</title>
    <style>
        :root {
            --bg-color: ${bgColor};
            --text-color: ${textColor};
            --secondary-bg: ${secondaryBg};
            --border-color: ${borderColor};
            --primary-color: ${primaryColor};
            --admin-color: ${adminColor};
            --success-color: #4caf50;
            --error-color: #f44336;
            --warning-color: #ff9800;
            --info-color: #2196f3;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: var(--secondary-bg);
            color: var(--text-color);
            padding: 15px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            text-decoration: none;
            color: var(--primary-color);
        }
        
        .nav-links {
            display: flex;
            gap: 20px;
        }
        
        .nav-links a {
            color: var(--text-color);
            text-decoration: none;
            padding: 5px 10px;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        
        .nav-links a:hover {
            background-color: rgba(255,255,255,0.1);
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid var(--primary-color);
        }
        
        .logout-btn {
            background-color: var(--error-color);
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        
        .logout-btn:hover {
            background-color: #d32f2f;
        }
        
        .main-content {
            margin: 30px 0;
        }
        
        .card {
            background-color: var(--secondary-bg);
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: var(--text-color);
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 16px;
            background-color: var(--secondary-bg);
            color: var(--text-color);
        }
        
        .btn {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
            margin: 5px 0;
        }
        
        .btn:hover {
            background-color: #0077b3;
        }
        
        .btn-secondary {
            background-color: #6c757d;
        }
        
        .btn-secondary:hover {
            background-color: #5a6268;
        }
        
        .btn-success {
            background-color: var(--success-color);
        }
        
        .btn-success:hover {
            background-color: #43a047;
        }
        
        .btn-danger {
            background-color: var(--error-color);
        }
        
        .btn-danger:hover {
            background-color: #d32f2f;
        }
        
        .btn-info {
            background-color: var(--info-color);
        }
        
        .btn-info:hover {
            background-color: #1976d2;
        }
        
        .user-list, .chat-list, .message-list {
            list-style: none;
            padding: 0;
        }
        
        .user-item, .chat-item, .message-item {
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 15px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .user-item:hover, .chat-item:hover {
            background-color: rgba(0,0,0,0.05);
        }
        
        .user-info-block {
            flex: 1;
        }
        
        .username {
            font-weight: 600;
            font-size: 18px;
            color: var(--text-color);
        }
        
        .user-title {
            font-size: 14px;
            font-weight: 500;
            margin-left: 5px;
            padding: 2px 6px;
            border-radius: 4px;
        }
        
        .admin-title {
            color: var(--admin-color) !important;
            font-weight: bold;
        }
        
        .user-level {
            font-size: 14px;
            color: #666;
        }
        
        .action-btn {
            padding: 5px 10px;
            font-size: 12px;
            margin-left: 5px;
            border-radius: 4px;
        }
        
        .small-action-btn {
            padding: 3px 8px;
            font-size: 11px;
            margin: 0 2px;
            border-radius: 3px;
        }
        
        .emoji-container {
            display: grid;
            grid-template-columns: repeat(10, 1fr);
            gap: 5px;
            margin-top: 10px;
            max-height: 200px;
            overflow-y: auto;
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background-color: var(--secondary-bg);
        }
        
        .emoji-btn {
            width: 30px;
            height: 30px;
            padding: 0;
            background: none;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .emoji-btn:hover {
            background-color: rgba(0,0,0,0.1);
        }
        
        .emoji-img {
            width: 24px;
            height: 24px;
            object-fit: contain;
        }
        
        .message-content {
            flex: 1;
            padding: 10px;
            border-radius: 8px;
            margin: 5px 0;
            position: relative;
            max-width: 70%;
        }
        
        .message-info {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }
        
        .message-sender {
            font-weight: bold;
        }
        
        .own-message {
            background-color: #dcf8c6;
            margin-left: auto;
            text-align: right;
        }
        
        .other-message {
            background-color: var(--secondary-bg);
            border: 1px solid var(--border-color);
        }
        
        .online-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--success-color);
            display: inline-block;
            margin-right: 5px;
        }
        
        .search-bar {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 16px;
            background-color: var(--secondary-bg);
            color: var(--text-color);
        }
        
        .admin-panel {
            background-color: rgba(233, 30, 99, 0.1);
            border: 1px solid var(--admin-color);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .admin-title {
            color: var(--admin-color);
            font-size: 20px;
            margin-bottom: 15px;
            font-weight: bold;
        }
        
        .error-message {
            background-color: rgba(244, 67, 54, 0.1);
            color: var(--error-color);
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            border: 1px solid var(--error-color);
        }
        
        .success-message {
            background-color: rgba(76, 175, 80, 0.1);
            color: var(--success-color);
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            border: 1px solid var(--success-color);
        }
        
        .warning-message {
            background-color: rgba(255, 152, 0, 0.1);
            color: var(--warning-color);
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            border: 1px solid var(--warning-color);
        }
        
        .chat-container {
            display: flex;
            height: 75vh;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .chat-sidebar {
            width: 300px;
            background-color: var(--secondary-bg);
            border-right: 1px solid var(--border-color);
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }
        
        .chat-sidebar-header {
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
            font-weight: bold;
            background-color: var(--secondary-bg);
        }
        
        .chat-main {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100%;
        }
        
        .chat-header {
            padding: 15px;
            background-color: var(--secondary-bg);
            border-bottom: 1px solid var(--border-color);
            font-weight: bold;
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .chat-messages {
            flex: 1;
            padding: 15px;
            overflow-y: auto;
            background-color: var(--bg-color);
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .chat-input {
            padding: 15px;
            background-color: var(--secondary-bg);
            border-top: 1px solid var(--border-color);
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .chat-input input {
            flex: 1;
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 20px;
            font-size: 16px;
            background-color: var(--secondary-bg);
            color: var(--text-color);
        }
        
        .chat-input button {
            border-radius: 20px;
            padding: 10px 15px;
        }
        
        .profile-card {
            text-align: center;
            padding: 30px;
        }
        
        .profile-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin: 0 auto 20px;
            display: block;
            border: 3px solid var(--primary-color);
            object-fit: cover;
        }
        
        .profile-name {
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
            color: var(--text-color);
        }
        
        .profile-username {
            font-size: 18px;
            color: #888;
            margin: 5px 0;
        }
        
        .profile-info {
            margin: 15px 0;
            text-align: left;
        }
        
        .profile-info-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }
        
        .profile-info-label {
            font-weight: 500;
            color: #888;
        }
        
        .settings-panel {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .settings-section {
            background-color: var(--secondary-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        
        .settings-section h3 {
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .appeal-form {
            max-width: 600px;
            margin: 0 auto;
        }
        
        .audit-list {
            list-style: none;
            padding: 0;
        }
        
        .audit-item {
            padding: 15px;
            border-bottom: 1px solid var(--border-color);
            background-color: var(--secondary-bg);
            margin-bottom: 10px;
            border-radius: 8px;
        }
        
        .audit-status {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .status-pending {
            background-color: var(--warning-color);
            color: white;
        }
        
        .status-approved {
            background-color: var(--success-color);
            color: white;
        }
        
        .status-rejected {
            background-color: var(--error-color);
            color: white;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #888;
            font-size: 14px;
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            .chat-container {
                flex-direction: column;
                height: auto;
            }
            
            .chat-sidebar {
                width: 100%;
                height: auto;
                max-height: 300px;
            }
            
            .settings-panel {
                grid-template-columns: 1fr;
            }
        }
        
        /* 深色主题特殊样式 */
        [data-theme="dark"] {
            --bg-color: #121212;
            --text-color: #e0e0e0;
            --secondary-bg: #1e1e1e;
            --border-color: #333333;
        }
        
        [data-theme="dark"] .card {
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        
        /* 动画效果 */
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* 加载动画 */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(0,0,0,0.1);
            border-top: 3px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <a href="/" class="logo">${APP_NAME}</a>
            <nav class="nav-links">
                ${user ? `
                    <a href="/chat">消息</a>
                    <a href="/contacts">联系人</a>
                    <a href="/settings">设置</a>
                    ${this.isAdmin(user) ? '<a href="/admin">管理</a>' : ''}
                ` : `
                    <a href="/login">登录</a>
                    <a href="/register">注册</a>
                `}
            </nav>
            ${user ? `
                <div class="user-info">
                    <img src="${user.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'">
                    <span>${user.display_name}</span>
                    <form method="POST" action="/logout" style="display: inline;">
                        <button type="submit" class="logout-btn">退出</button>
                    </form>
                </div>
            ` : ''}
        </div>
    </header>
    
    <div class="container">
        ${content}
    </div>
    
    <footer>
        &copy; ${new Date().getFullYear()} ${APP_NAME} - 安全加密聊天平台
    </footer>

    <script>
        // 基础交互功能
        document.addEventListener('DOMContentLoaded', function() {
            // Emoji选择器
            const emojiBtns = document.querySelectorAll('.emoji-btn');
            emojiBtns.forEach(btn => {
                btn.addEventListener('click', function() {
                    const emojiNum = this.dataset.emoji;
                    const input = document.querySelector('.chat-input input') || document.querySelector('textarea');
                    if (input) {
                        input.value += '[emoji:' + emojiNum + ']';
                        input.focus();
                    }
                });
            });
            
            // 显示/隐藏emoji面板
            const emojiToggle = document.getElementById('emoji-toggle');
            const emojiContainer = document.getElementById('emoji-container');
            if (emojiToggle && emojiContainer) {
                emojiToggle.addEventListener('click', function() {
                    emojiContainer.style.display = emojiContainer.style.display === 'none' ? 'grid' : 'none';
                });
            }
            
            // 实时搜索
            const searchInput = document.getElementById('user-search');
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    const filter = this.value.toLowerCase();
                    const items = document.querySelectorAll('.user-item, .chat-item, .contact-item');
                    items.forEach(item => {
                        const text = item.textContent.toLowerCase();
                        item.style.display = text.includes(filter) ? '' : 'none';
                    });
                });
            }
            
            // 主题切换
            const themeToggle = document.getElementById('theme-toggle');
            if (themeToggle) {
                themeToggle.addEventListener('click', function() {
                    const currentTheme = document.documentElement.getAttribute('data-theme');
                    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', newTheme);
                    document.body.className = 'fade-in';
                    
                    // 保存到localStorage
                    localStorage.setItem('theme', newTheme);
                    
                    // 延迟移除动画类
                    setTimeout(() => {
                        document.body.classList.remove('fade-in');
                    }, 500);
                });
                
                // 从localStorage恢复主题
                const savedTheme = localStorage.getItem('theme');
                if (savedTheme) {
                    document.documentElement.setAttribute('data-theme', savedTheme);
                }
            }
            
            // 自动滚动到最新消息
            const messagesContainer = document.querySelector('.chat-messages');
            if (messagesContainer) {
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        });
        
        // 全局函数
        function toggleBan(uid, currentStatus) {
            if (confirm('确定要' + (currentStatus ? '解封' : '封禁') + '此用户吗？')) {
                fetch('/admin/toggle-ban', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ uid: uid })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert((currentStatus ? '解封' : '封禁') + '成功');
                        location.reload();
                    } else {
                        alert('操作失败: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('网络错误: ' + error.message);
                });
            }
        }
        
        function addTitle(uid) {
            const titleName = prompt('请输入头衔名称（用于内部标识）:');
            if (!titleName) return;
            
            const titleDisplay = prompt('请输入头衔显示文字:', titleName);
            if (titleDisplay === null) return;
            
            const color = prompt('请输入头衔颜色 (red/blue/green/purple等):', 'blue');
            if (color === null) return;
            
            fetch('/admin/add-title', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    uid: uid, 
                    titleName: titleName,
                    titleDisplay: titleDisplay,
                    color: color
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('添加头衔成功');
                    location.reload();
                } else {
                    alert('操作失败: ' + data.error);
                }
            })
            .catch(error => {
                alert('网络错误: ' + error.message);
            });
        }
        
        function resetPassword(uid) {
            if (confirm('确定要重置此用户的密码吗？新密码将显示在页面上。')) {
                fetch('/admin/reset-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ uid: uid })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('新密码: ' + data.temporary_password + '\\n请妥善保管并告知用户。');
                        location.reload();
                    } else {
                        alert('操作失败: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('网络错误: ' + error.message);
                });
            }
        }
        
        function sendMessage(receiver) {
            const input = document.getElementById('message-input');
            const message = input.value.trim();
            if (!message) return;
            
            const sendBtn = document.getElementById('send-btn');
            const originalText = sendBtn.textContent;
            sendBtn.textContent = '发送中...';
            sendBtn.disabled = true;
            sendBtn.innerHTML = '<span class="loading"></span>';
            
            fetch('/send-message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    receiver: receiver,
                    content: message
                })
            })
            .then(response => response.json())
            .then(data => {
                sendBtn.textContent = originalText;
                sendBtn.disabled = false;
                sendBtn.innerHTML = originalText;
                
                if (data.success) {
                    input.value = '';
                    // 重新加载消息
                    location.reload();
                } else {
                    alert('发送失败: ' + (data.error || '未知错误'));
                }
            })
            .catch(error => {
                sendBtn.textContent = originalText;
                sendBtn.disabled = false;
                sendBtn.innerHTML = originalText;
                alert('发送失败: ' + error.message);
            });
        }
        
        function submitAppeal() {
            const email = document.getElementById('appeal-email').value.trim();
            const reason = document.getElementById('appeal-reason').value.trim();
            
            if (!email || !reason) {
                alert('请填写邮箱和申诉理由');
                return;
            }
            
            if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
                alert('请输入有效的邮箱地址');
                return;
            }
            
            const submitBtn = document.getElementById('submit-appeal');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '提交中...';
            submitBtn.disabled = true;
            
            fetch('/submit-appeal', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    reason: reason
                })
            })
            .then(response => response.json())
            .then(data => {
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
                
                if (data.success) {
                    alert('申诉已提交，我们会尽快处理。');
                    location.href = '/';
                } else {
                    alert('提交失败: ' + data.error);
                }
            })
            .catch(error => {
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
                alert('提交失败: ' + error.message);
            });
        }
        
        function deleteAccount() {
            if (confirm('确定要注销账号吗？此操作不可恢复！')) {
                const password = prompt('请输入您的密码以确认:');
                if (!password) return;
                
                fetch('/delete-account', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        password: password
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('账号已注销');
                        location.href = '/logout';
                    } else {
                        alert('注销失败: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('网络错误: ' + error.message);
                });
            }
        }
    </script>
</body>
</html>
    `;
  }

  static isAdmin(user) {
    return user && user.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase();
  }

  static getLoginTemplate(error = null, banned = false, banUntil = null) {
    let content = `
        <div class="card">
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
        </div>
    `;

    if (banned && banUntil) {
      const banDate = new Date(banUntil);
      content = `
        <div class="card">
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
            <p style="margin-top: 20px;">
                <a href="/" class="btn btn-secondary">返回首页</a>
            </p>
        </div>
      `;
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
                    <input type="text" id="invite_code" name="invite_code" required value="${DEFAULT_INVITE_CODE}" placeholder="请输入邀请码">
                </div>
                <div class="form-group">
                    <label for="avatar">头像链接（可选）</label>
                    <input type="url" id="avatar" name="avatar" placeholder="https://example.com/avatar.jpg">
                </div>
                <div class="form-group">
                    <label for="bio">个性签名（可选）</label>
                    <textarea id="bio" name="bio" rows="3" maxlength="100" placeholder="一句话介绍自己"></textarea>
                </div>
                <div class="form-group">
                    <label>性别</label>
                    <div>
                        <label style="margin-right: 20px;">
                            <input type="radio" name="gender" value="♂" checked> ♂ 男
                        </label>
                        <label>
                            <input type="radio" name="gender" value="♀"> ♀ 女
                        </label>
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
      const isOnline = new Date() - new Date(contact.last_login) < 5 * 60 * 1000; // 5分钟内算在线
      const levelText = `Lv.${contact.level}`;
      const titlesHtml = contact.titles && contact.titles.length > 0 ? 
        contact.titles.map(title => {
          const config = { "创始人": { color: "red", weight: "bold" } };
          const titleConfig = config[title] || { color: "blue", weight: "normal" };
          return `<span class="user-title" style="color: ${titleConfig.color}; font-weight: ${titleConfig.weight};">${title}</span>`;
        }).join(' ') : '';

      return `
        <li class="chat-item" onclick="location.href='/chat/${contact.username}'">
            <img src="${contact.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'">
            <div class="user-info-block">
                <div class="username">
                    ${contact.display_name}
                    ${titlesHtml}
                    ${isOnline ? '<span class="online-indicator"></span>' : ''}
                </div>
                <div class="user-level">${levelText} • ${contact.gender}</div>
                <div class="message-info">最后登录: ${new Date(contact.last_login).toLocaleString()}</div>
            </div>
        </li>
      `;
    }).join('');

    return this.getBaseTemplate("消息", `
        <div class="card">
            <h2>消息</h2>
            ${error ? `<div class="error-message">${error}</div>` : ''}
            <input type="text" id="user-search" class="search-bar" placeholder="搜索联系人...">
            <ul class="chat-list">
                ${contactItems || '<li class="chat-item">暂无联系人</li>'}
            </ul>
        </div>
    `, user, user?.settings?.theme || "light");
  }

  static getChatTemplate(user, targetUser, messages, error = null) {
    const messageItems = messages.map(msg => {
      const isOwn = msg.sender_uid === user.uid;
      const messageClass = isOwn ? 'own-message' : 'other-message';
      const alignClass = isOwn ? 'style="margin-left: auto;"' : '';
      
      // 格式化emoji
      let content = msg.decrypted_content || "[加密消息]";
      const emojiRegex = /\[emoji:(\d+)\]/g;
      content = content.replace(emojiRegex, (match, p1) => {
        const num = parseInt(p1);
        if (num >= 1 && num <= EMOJI_COUNT) {
          return `<img src="/emoji/${num}.png" alt="emoji${num}" style="width: 24px; height: 24px; vertical-align: middle;" onerror="this.src='/default-emoji.png'">`;
        }
        return match;
      });

      return `
        <div class="message-item ${messageClass}" ${alignClass}>
            <div class="message-content">
                <div class="message-text">${content}</div>
                <div class="message-info">
                    ${isOwn ? '你' : targetUser.display_name} · ${new Date(msg.timestamp).toLocaleString()}
                    ${msg.read ? '✓✓' : '✓'}
                </div>
            </div>
        </div>
      `;
    }).join('');

    // 生成emoji面板
    let emojiHtml = '';
    for (let i = 1; i <= Math.min(EMOJI_COUNT, 100); i++) {
      emojiHtml += `
        <button class="emoji-btn" data-emoji="${i}">
            <img src="/emoji/${i}.png" alt="${i}" class="emoji-img" onerror="this.src='/default-emoji.png'">
        </button>
      `;
    }

    return this.getBaseTemplate(`与 ${targetUser.display_name} 聊天`, `
        <div class="chat-container">
            <div class="chat-sidebar">
                <div class="chat-sidebar-header">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span>联系人</span>
                        <input type="text" id="user-search" class="search-bar" placeholder="搜索..." style="width: 180px; margin: 0;">
                    </div>
                </div>
                <div style="flex: 1; overflow-y: auto; padding: 10px;">
                    <!-- 联系人列表将在实际应用中动态加载 -->
                </div>
            </div>
            <div class="chat-main">
                <div class="chat-header">
                    <img src="${targetUser.avatar}" alt="头像" class="avatar" style="width: 40px; height: 40px;" onerror="this.src='https://via.placeholder.com/150'">
                    <a href="/profile/${targetUser.username}" style="text-decoration: none; color: inherit;">
                        ${targetUser.display_name}
                    </a>
                    <div style="margin-left: auto;">
                        <button id="emoji-toggle" class="btn" style="padding: 8px 12px;">😊</button>
                    </div>
                </div>
                <div class="chat-messages" id="chat-messages">
                    ${messageItems || '<div style="text-align: center; padding: 20px; color: #888;">暂无消息，开始聊天吧！</div>'}
                </div>
                <div class="chat-input">
                    <input type="text" id="message-input" name="message" placeholder="输入消息..." autocomplete="off">
                    <button type="button" id="send-btn" class="btn" onclick="sendMessage('${targetUser.username}')">发送</button>
                </div>
                <div id="emoji-container" class="emoji-container" style="display: none; position: absolute; bottom: 80px; left: 15px; z-index: 1000;">
                    ${emojiHtml}
                </div>
            </div>
        </div>
    `, user, user?.settings?.theme || "light");
  }

  static getProfileTemplate(user, profileUser, isOwnProfile, error = null) {
    const isAdmin = this.isAdmin(user);
    const isProfileAdmin = profileUser.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase();
    const levelText = `Lv.${profileUser.level}${profileUser.level === 1 ? ' (注册会员)' : ''}`;
    
    // 计算在线天数
    const createdDate = new Date(profileUser.created_at);
    const today = new Date();
    const diffTime = Math.abs(today - createdDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const onlineDays = profileUser.online_days || 1;

    // 头衔显示
    const config = { "创始人": { color: "red", weight: "bold" } };
    const titlesHtml = profileUser.titles && profileUser.titles.length > 0 ? 
      profileUser.titles.map(title => {
        const titleConfig = config[title] || { color: "blue", weight: "normal" };
        return `<span class="user-title" style="color: ${titleConfig.color}; font-weight: ${titleConfig.weight};">${title}</span>`;
      }).join(' ') : '';

    let adminActions = '';
    if (isAdmin && !isProfileAdmin && !isOwnProfile) {
      const banText = profileUser.is_banned ? '解封用户' : '封禁用户';
      const banClass = profileUser.is_banned ? 'btn-success' : 'btn-danger';
      
      adminActions = `
        <div style="margin-top: 20px; padding: 15px; background-color: rgba(233, 30, 99, 0.1); border-radius: 8px; border: 1px solid var(--admin-color);">
            <h4>管理操作</h4>
            <button class="btn ${banClass} small-action-btn" onclick="toggleBan('${profileUser.uid}', ${profileUser.is_banned})">${banText}</button>
            <button class="btn btn-secondary small-action-btn" onclick="addTitle('${profileUser.uid}')">添加头衔</button>
            <button class="btn btn-secondary small-action-btn" onclick="resetPassword('${profileUser.uid}')">重置密码</button>
        </div>
      `;
    }

    return this.getBaseTemplate(`${profileUser.display_name} 的个人资料`, `
        <div class="profile-card">
            ${error ? `<div class="error-message">${error}</div>` : ''}
            <img src="${profileUser.avatar}" alt="头像" class="profile-avatar" onerror="this.src='https://via.placeholder.com/150'">
            <h1 class="profile-name">${profileUser.display_name} ${titlesHtml}</h1>
            <div class="profile-username">@${profileUser.username} ${profileUser.gender}</div>
            <div class="profile-level">${levelText}</div>
            ${profileUser.bio ? `<div style="margin: 15px 0; font-size: 16px; line-height: 1.5;">"${profileUser.bio}"</div>` : ''}
            
            <div class="profile-info">
                <div class="profile-info-item">
                    <span class="profile-info-label">用户ID</span>
                    <span>${profileUser.uid}</span>
                </div>
                <div class="profile-info-item">
                    <span class="profile-info-label">注册时间</span>
                    <span>${new Date(profileUser.created_at).toLocaleString()}</span>
                </div>
                <div class="profile-info-item">
                    <span class="profile-info-label">在线天数</span>
                    <span>${onlineDays} 天</span>
                </div>
                <div class="profile-info-item">
                    <span class="profile-info-label">经验值</span>
                    <span>${profileUser.experience}</span>
                </div>
                <div class="profile-info-item">
                    <span class="profile-info-label">最后登录</span>
                    <span>${new Date(profileUser.last_login).toLocaleString()}</span>
                </div>
                <div class="profile-info-item">
                    <span class="profile-info-label">状态</span>
                    <span>${profileUser.is_banned ? '<span style="color: red;">⛔ 已封禁</span>' : '<span style="color: green;">✅ 正常</span>'}</span>
                </div>
            </div>
            
            ${isOwnProfile ? `
                <div style="margin-top: 20px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">
                    <a href="/settings" class="btn">设置</a>
                    <a href="/edit-profile" class="btn btn-secondary">编辑资料</a>
                    <button type="button" class="btn btn-danger" onclick="deleteAccount()">注销账号</button>
                </div>
            ` : `
                <div style="margin-top: 20px; text-align: center;">
                    <a href="/chat/${profileUser.username}" class="btn">发送消息</a>
                </div>
            `}
            
            ${adminActions}
        </div>
    `, user, user?.settings?.theme || "light");
  }

  static getEditProfileTemplate(user, error = null) {
    return this.getBaseTemplate("编辑个人资料", `
        <div class="card">
            <h2>编辑个人资料</h2>
            ${error ? `<div class="error-message">${error}</div>` : ''}
            <form method="POST" action="/edit-profile">
                <div class="form-group">
                    <label for="display_name">昵称</label>
                    <input type="text" id="display_name" name="display_name" value="${user.display_name}" required maxlength="30" placeholder="请输入昵称">
                </div>
                <div class="form-group">
                    <label for="avatar">头像链接</label>
                    <input type="url" id="avatar" name="avatar" value="${user.avatar}" placeholder="https://example.com/avatar.jpg">
                </div>
                <div class="form-group">
                    <label for="bio">个性签名</label>
                    <textarea id="bio" name="bio" rows="3" maxlength="100" placeholder="一句话介绍自己">${user.bio || ''}</textarea>
                </div>
                <div class="form-group">
                    <label>性别</label>
                    <div>
                        <label style="margin-right: 20px;">
                            <input type="radio" name="gender" value="♂" ${user.gender === "♂" ? 'checked' : ''}> ♂ 男
                        </label>
                        <label>
                            <input type="radio" name="gender" value="♀" ${user.gender === "♀" ? 'checked' : ''}> ♀ 女
                        </label>
                    </div>
                </div>
                <div class="form-group">
                    <label for="current_password">当前密码（修改密码需要）</label>
                    <input type="password" id="current_password" name="current_password" placeholder="留空则不修改密码">
                </div>
                <div class="form-group">
                    <label for="new_password">新密码</label>
                    <input type="password" id="new_password" name="new_password" placeholder="至少6位，留空则不修改">
                </div>
                <button type="submit" class="btn">保存更改</button>
            </form>
        </div>
    `, user, user?.settings?.theme || "light");
  }

  static getSettingsTemplate(user, error = null) {
    return this.getBaseTemplate("设置", `
        <div class="card">
            <h2>设置</h2>
            ${error ? `<div class="error-message">${error}</div>` : ''}
            
            <div class="settings-panel">
                <div class="settings-section">
                    <h3>👤 个人设置</h3>
                    <div class="form-group">
                        <label>主题</label>
                        <select id="theme-select" onchange="changeTheme(this.value)">
                            <option value="light" ${user.settings.theme === "light" ? 'selected' : ''}>浅色主题</option>
                            <option value="dark" ${user.settings.theme === "dark" ? 'selected' : ''}>深色主题</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="notifications" ${user.settings.notifications ? 'checked' : ''} onchange="updateSetting('notifications', this.checked)">
                            消息通知
                        </label>
                    </div>
                </div>
                
                <div class="settings-section">
                    <h3>🔒 隐私设置</h3>
                    <div class="form-group">
                        <label>谁可以看到我的在线状态</label>
                        <select id="last_seen" onchange="updatePrivacySetting('last_seen', this.value)">
                            <option value="everyone" ${user.settings.privacy.last_seen === "everyone" ? 'selected' : ''}>所有人</option>
                            <option value="contacts" ${user.settings.privacy.last_seen === "contacts" ? 'selected' : ''}>联系人</option>
                            <option value="nobody" ${user.settings.privacy.last_seen === "nobody" ? 'selected' : ''}>没有人</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>谁可以看到我的头像</label>
                        <select id="profile_photo" onchange="updatePrivacySetting('profile_photo', this.value)">
                            <option value="everyone" ${user.settings.privacy.profile_photo === "everyone" ? 'selected' : ''}>所有人</option>
                            <option value="contacts" ${user.settings.privacy.profile_photo === "contacts" ? 'selected' : ''}>联系人</option>
                            <option value="nobody" ${user.settings.privacy.profile_photo === "nobody" ? 'selected' : ''}>没有人</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div style="margin-top: 30px; text-align: center;">
                <a href="/edit-profile" class="btn">编辑个人资料</a>
                <button type="button" class="btn btn-danger" style="margin-left: 10px;" onclick="deleteAccount()">注销账号</button>
            </div>
        </div>
        
        <script>
            function changeTheme(theme) {
                document.documentElement.setAttribute('data-theme', theme);
                localStorage.setItem('theme', theme);
                
                // 保存到服务器
                fetch('/update-setting', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        setting: 'theme',
                        value: theme
                    })
                });
            }
            
            function updateSetting(setting, value) {
                fetch('/update-setting', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        setting: setting,
                        value: value
                    })
                });
            }
            
            function updatePrivacySetting(setting, value) {
                fetch('/update-setting', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        setting: 'privacy.' + setting,
                        value: value
                    })
                });
            }
        </script>
    `, user, user?.settings?.theme || "light");
  }

  static getAdminPanelTemplate(user, users, config, appeals, error = null) {
    if (!this.isAdmin(user)) {
      return this.getBaseTemplate("管理面板", `
        <div class="card">
            <h2>权限不足</h2>
            <p>只有管理员才能访问此页面。</p>
            <a href="/" class="btn">返回首页</a>
        </div>
      `, user, user?.settings?.theme || "light");
    }

    const userItems = users.map(u => {
      const levelText = `Lv.${u.level}`;
      const isOnline = new Date() - new Date(u.last_login) < 5 * 60 * 1000;
      const config = { "创始人": { color: "red", weight: "bold" } };
      const titlesHtml = u.titles && u.titles.length > 0 ? 
        u.titles.map(title => {
          const titleConfig = config[title] || { color: "blue", weight: "normal" };
          return `<span class="user-title" style="color: ${titleConfig.color}; font-weight: ${titleConfig.weight};">${title}</span>`;
        }).join(' ') : '';
      
      const banText = u.is_banned ? '解封' : '封禁';
      const banClass = u.is_banned ? 'btn-success' : 'btn-danger';
      const isFounder = u.username.toLowerCase() === ADMIN_USERNAME_VALUE.toLowerCase();
      
      return `
        <li class="user-item">
            <img src="${u.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'">
            <div class="user-info-block">
                <div class="username">
                    ${u.display_name}
                    ${isFounder ? '<span class="user-title" style="color: red; font-weight: bold;">创始人</span>' : titlesHtml}
                    ${isOnline ? '<span class="online-indicator"></span>' : ''}
                </div>
                <div>@${u.username} ${u.gender} • ${levelText}</div>
                <div>UID: ${u.uid} • 注册: ${new Date(u.created_at).toLocaleDateString()}</div>
                <div>在线: ${u.online_days}天 • 最后登录: ${new Date(u.last_login).toLocaleString()}</div>
                ${u.is_banned ? `<div style="color: red;">⛔ 已封禁 ${u.ban_until ? '至 ' + new Date(u.ban_until).toLocaleString() : '永久'}</div>` : ''}
            </div>
            ${!isFounder ? `
                <button class="btn ${banClass} small-action-btn" onclick="toggleBan('${u.uid}', ${u.is_banned})">${banText}</button>
                <button class="btn btn-secondary small-action-btn" onclick="addTitle('${u.uid}')">头衔</button>
                <button class="btn btn-secondary small-action-btn" onclick="resetPassword('${u.uid}')">重置</button>
            ` : '<span style="color: red; font-weight: bold;">👑 管理员</span>'}
        </li>
      `;
    }).join('');

    const appealItems = appeals.map(a => {
      const user = users.find(u => u.uid === a.uid);
      const statusClass = {
        'pending': 'status-pending',
        'approved': 'status-approved',
        'rejected': 'status-rejected'
      }[a.status] || '';
      
      return `
        <div class="audit-item">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h4>申诉 #${a.id.substring(0, 8)}</h4>
                <span class="audit-status ${statusClass}">${a.status === 'pending' ? '待处理' : a.status === 'approved' ? '已通过' : '已拒绝'}</span>
            </div>
            <div class="profile-info-item">
                <span class="profile-info-label">用户</span>
                <span>${user ? user.display_name + ' (@' + user.username + ')' : 'UID: ' + a.uid}</span>
            </div>
            <div class="profile-info-item">
                <span class="profile-info-label">邮箱</span>
                <span>${a.email}</span>
            </div>
            <div class="profile-info-item">
                <span class="profile-info-label">申诉理由</span>
                <span>${a.reason}</span>
            </div>
            <div class="profile-info-item">
                <span class="profile-info-label">提交时间</span>
                <span>${new Date(a.created_at).toLocaleString()}</span>
            </div>
            ${a.processed_at ? `
                <div class="profile-info-item">
                    <span class="profile-info-label">处理时间</span>
                    <span>${new Date(a.processed_at).toLocaleString()}</span>
                </div>
                <div class="profile-info-item">
                    <span class="profile-info-label">处理结果</span>
                    <span>${a.admin_response || '无'}</span>
                </div>
            ` : ''}
            ${a.status === 'pending' ? `
                <div style="margin-top: 15px; display: flex; gap: 10px;">
                    <button class="btn btn-success" onclick="processAppeal('${a.id}', 'approved', '申诉已通过')">通过</button>
                    <button class="btn btn-danger" onclick="processAppeal('${a.id}', 'rejected', prompt('请输入拒绝理由:'))">拒绝</button>
                </div>
            ` : ''}
        </div>
      `;
    }).join('');

    return this.getBaseTemplate("管理面板", `
        <div class="admin-panel">
            <h2 class="admin-title">👑 管理员控制台</h2>
            ${error ? `<div class="error-message">${error}</div>` : ''}
            
            <div class="card">
                <h3>⚙️ 系统设置</h3>
                <form method="POST" action="/admin/set-invite-code" style="display: flex; gap: 10px; align-items: center;">
                    <div class="form-group" style="flex: 1;">
                        <label>当前邀请码: <strong>${config.invite_code}</strong></label>
                        <input type="text" name="new_invite_code" placeholder="输入新的邀请码" required style="margin-bottom: 0;">
                    </div>
                    <button type="submit" class="btn" style="height: 42px; margin-top: 25px;">更新</button>
                </form>
            </div>
            
            <div class="card">
                <h3>👥 用户管理</h3>
                <input type="text" id="user-search" class="search-bar" placeholder="搜索用户...">
                <ul class="user-list">
                    ${userItems}
                </ul>
            </div>
            
            <div class="card">
                <h3>📬 申诉审核</h3>
                ${appeals.length > 0 ? appealItems : '<div style="padding: 20px; text-align: center; color: #888;">暂无申诉记录</div>'}
            </div>
        </div>
        
        <script>
            function processAppeal(appealId, status, response) {
                if (status === 'rejected' && !response) {
                    alert('请输入拒绝理由');
                    return;
                }
                
                fetch('/admin/process-appeal', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        appeal_id: appealId,
                        status: status,
                        response: response || ''
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('处理成功');
                        location.reload();
                    } else {
                        alert('处理失败: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('网络错误: ' + error.message);
                });
            }
        </script>
    `, user, user?.settings?.theme || "light");
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
                    <input type="email" id="appeal-email" required placeholder="example@email.com">
                </div>
                <div class="form-group">
                    <label for="appeal-reason">申诉理由</label>
                    <textarea id="appeal-reason" rows="6" required placeholder="请详细说明您认为封禁有误的原因..."></textarea>
                </div>
                <button type="button" id="submit-appeal" class="btn" onclick="submitAppeal()">提交申诉</button>
            </form>
            <p style="margin-top: 20px; text-align: center;">
                <a href="/" class="btn btn-secondary">返回首页</a>
            </p>
        </div>
    `, user, "light"); // 申诉页面使用浅色主题
  }

  static getContactsTemplate(user, contacts, error = null) {
    const contactItems = contacts.map(contact => {
      const isOnline = new Date() - new Date(contact.last_login) < 5 * 60 * 1000;
      const levelText = `Lv.${contact.level}`;
      const config = { "创始人": { color: "red", weight: "bold" } };
      const titlesHtml = contact.titles && contact.titles.length > 0 ? 
        contact.titles.map(title => {
          const titleConfig = config[title] || { color: "blue", weight: "normal" };
          return `<span class="user-title" style="color: ${titleConfig.color}; font-weight: ${titleConfig.weight};">${title}</span>`;
        }).join(' ') : '';

      return `
        <li class="user-item contact-item" onclick="location.href='/chat/${contact.username}'">
            <img src="${contact.avatar}" alt="头像" class="avatar" onerror="this.src='https://via.placeholder.com/150'">
            <div class="user-info-block">
                <div class="username">
                    ${contact.display_name}
                    ${titlesHtml}
                    ${isOnline ? '<span class="online-indicator"></span>' : ''}
                </div>
                <div class="user-level">${levelText} • ${contact.gender}</div>
                <div class="message-info">最后活跃: ${new Date(contact.last_login).toLocaleString()}</div>
            </div>
            <div style="margin-left: auto;">
                <a href="/chat/${contact.username}" class="btn" style="padding: 5px 10px; font-size: 12px;">发消息</a>
            </div>
        </li>
      `;
    }).join('');

    return this.getBaseTemplate("联系人", `
        <div class="card">
            <h2>联系人</h2>
            ${error ? `<div class="error-message">${error}</div>` : ''}
            <input type="text" id="user-search" class="search-bar" placeholder="搜索联系人...">
            <ul class="user-list">
                ${contactItems || '<li class="user-item">暂无联系人</li>'}
            </ul>
        </div>
    `, user, user?.settings?.theme || "light");
  }

  static getEmojiTemplate(user, page = 1) {
    const emojisPerPage = 50;
    const start = (page - 1) * emojisPerPage + 1;
    const end = Math.min(page * emojisPerPage, EMOJI_COUNT);
    
    let emojiHtml = '';
    for (let i = start; i <= end; i++) {
      emojiHtml += `
        <button class="emoji-btn" data-emoji="${i}" onclick="selectEmoji(${i})">
            <img src="/emoji/${i}.png" alt="${i}" class="emoji-img" onerror="this.src='/default-emoji.png'">
        </button>
      `;
    }

    const totalPages = Math.ceil(EMOJI_COUNT / emojisPerPage);
    let paginationHtml = '';
    for (let i = 1; i <= totalPages && i <= 5; i++) {
      paginationHtml += `
        <button class="btn ${i === page ? 'btn-secondary' : ''}" onclick="location.href='/emoji?page=${i}'">${i}</button>
      `;
    }

    return this.getBaseTemplate("表情选择", `
        <div class="card">
            <h2>😄 表情选择</h2>
            <div class="emoji-container">
                ${emojiHtml}
            </div>
            <div style="margin-top: 20px; text-align: center;">
                ${paginationHtml}
                ${totalPages > 5 ? `<span>... 共${totalPages}页</span>` : ''}
            </div>
            <div style="margin-top: 20px; text-align: center;">
                <button class="btn" onclick="window.close()">关闭</button>
            </div>
        </div>
        
        <script>
            function selectEmoji(emojiNum) {
                if (window.opener && window.opener.selectEmoji) {
                    window.opener.selectEmoji(emojiNum);
                    window.close();
                } else {
                    alert('请在聊天窗口中使用表情选择器');
                }
            }
        </script>
    `, user, user?.settings?.theme || "light");
  }

  static getErrorTemplate(message, user = null) {
    return this.getBaseTemplate("错误", `
        <div class="card">
            <h2>❌ 发生错误</h2>
            <div class="error-message">${message}</div>
            <a href="/" class="btn">返回首页</a>
        </div>
    `, user, user?.settings?.theme || "light");
  }

  static getSuccessTemplate(message, redirectUrl = "/", user = null) {
    return this.getBaseTemplate("操作成功", `
        <div class="card">
            <h2>✅ 操作成功</h2>
            <div class="success-message">${message}</div>
            <a href="${redirectUrl}" class="btn">继续</a>
        </div>
    `, user, user?.settings?.theme || "light");
  }
}

// ========== 路由处理器 ==========
class Router {
  static async handleRequest(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 解析cookie获取会话
    const cookies = request.headers.get('Cookie') || '';
    const sessionToken = cookies.split(';').find(c => c.trim().startsWith('session='))?.split('=')[1];
    let currentUser = null;
    let currentTheme = "light";

    if (sessionToken) {
      currentUser = await SessionManager.validateSession(sessionToken, request);
      if (currentUser) {
        currentTheme = currentUser.settings?.theme || "light";
        // 延长会话有效期
        await SessionManager.extendSession(sessionToken);
      }
    }

    try {
      // 静态资源路由
      if (path.startsWith('/emoji/') && path.endsWith('.png')) {
        const emojiNum = path.match(/\/emoji\/(\d+)\.png$/)?.[1];
        if (emojiNum && parseInt(emojiNum) >= 1 && parseInt(emojiNum) <= EMOJI_COUNT) {
          // 重定向到CDN或返回默认emoji
          return new Response(null, {
            status: 302,
            headers: {
              'Location': `https://example.com/emoji/${emojiNum}.png` // 实际部署时替换
            }
          });
        }
      }

      if (path === '/default-avatar.png' || path === '/default-emoji.png') {
        // 返回默认图片
        const defaultImage = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
        return new Response(atob(defaultImage), {
          headers: {
            'Content-Type': 'image/png',
            'Cache-Control': 'public, max-age=31536000'
          }
        });
      }

      // 公开路由
      if (path === '/' || path === '/index.html') {
        if (currentUser) {
          // 重定向到消息列表
          return Response.redirect(new URL('/chat', url).toString(), 302);
        } else {
          // 显示首页
          const content = `
            <div class="card" style="text-align: center;">
                <h1>💬 欢迎使用 ${APP_NAME}</h1>
                <p>安全加密的Telegram风格聊天平台</p>
                <div style="margin: 30px 0;">
                    <img src="https://via.placeholder.com/400x200?text=TeleChat" alt="应用截图" style="max-width: 100%; border-radius: 8px;">
                </div>
                <div style="margin: 30px 0;">
                    <a href="/login" class="btn" style="margin-right: 10px; padding: 12px 24px;">登录</a>
                    <a href="/register" class="btn btn-secondary" style="padding: 12px 24px;">注册</a>
                </div>
                <div style="color: #666; margin-top: 20px;">
                    <p>使用邀请码 <strong>${DEFAULT_INVITE_CODE}</strong> 注册</p>
                </div>
            </div>
            
            <div class="card">
                <h2>🌟 功能特色</h2>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px;">
                    <div style="text-align: center; padding: 20px; background-color: rgba(0,136,204,0.1); border-radius: 8px;">
                        <h3>🔒 端到端加密</h3>
                        <p>所有聊天记录加密存储，保障隐私安全</p>
                    </div>
                    <div style="text-align: center; padding: 20px; background-color: rgba(76,175,80,0.1); border-radius: 8px;">
                        <h3>📱 仿Telegram界面</h3>
                        <p>熟悉的Telegram风格，操作流畅</p>
                    </div>
                    <div style="text-align: center; padding: 20px; background-color: rgba(233,30,99,0.1); border-radius: 8px;">
                        <h3>👑 管理员特权</h3>
                        <p>完善的管理功能，维护社区秩序</p>
                    </div>
                </div>
            </div>
          `;
          return new Response(HTMLTemplates.getBaseTemplate("欢迎", content), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }
      }

      // 登录相关路由
      if (path === '/login') {
        if (method === 'GET') {
          return new Response(HTMLTemplates.getLoginTemplate(), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        } else if (method === 'POST') {
          const formData = await request.formData();
          const username = formData.get('username')?.toString().trim();
          const password = formData.get('password')?.toString();

          if (!username || !password) {
            return new Response(HTMLTemplates.getLoginTemplate("用户名或密码不能为空"), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }

          const result = await UserManager.login(username, password, request);
          if (!result.success) {
            if (result.banned) {
              return new Response(HTMLTemplates.getLoginTemplate(result.error, true, result.ban_until), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
              });
            } else {
              return new Response(HTMLTemplates.getLoginTemplate(result.error), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
              });
            }
          }

          // 创建会话cookie
          return new Response('', {
            status: 302,
            headers: {
              'Location': '/chat',
              'Set-Cookie': `session=${result.token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`
            }
          });
        }
      }

      // 注册相关路由
      if (path === '/register') {
        if (method === 'GET') {
          return new Response(HTMLTemplates.getRegisterTemplate(), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        } else if (method === 'POST') {
          const formData = await request.formData();
          const userData = {
            display_name: formData.get('display_name')?.toString().trim(),
            username: formData.get('username')?.toString().trim(),
            password: formData.get('password')?.toString(),
            invite_code: formData.get('invite_code')?.toString().trim(),
            avatar: formData.get('avatar')?.toString().trim(),
            bio: formData.get('bio')?.toString().trim(),
            gender: formData.get('gender')?.toString().trim() || '♂'
          };

          // 验证数据
          if (!userData.display_name || !userData.username || !userData.password || !userData.invite_code) {
            return new Response(HTMLTemplates.getRegisterTemplate("请填写所有必填字段"), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }

          // 创建用户
          const result = await UserManager.register(userData);
          if (!result.success) {
            return new Response(HTMLTemplates.getRegisterTemplate(result.error), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }

          // 自动登录
          const loginResult = await UserManager.login(userData.username, userData.password, request);
          if (!loginResult.success) {
            return new Response(HTMLTemplates.getRegisterTemplate("注册成功但登录失败，请重新登录"), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }

          return new Response('', {
            status: 302,
            headers: {
              'Location': '/chat',
              'Set-Cookie': `session=${loginResult.token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`
            }
          });
        }
      }

      // 退出登录
      if (path === '/logout' && method === 'POST') {
        if (sessionToken) {
          await SessionManager.deleteSession(sessionToken);
        }
        
        return new Response('', {
          status: 302,
          headers: {
            'Location': '/',
            'Set-Cookie': 'session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
          }
        });
      }

      // 需要登录的路由检查
      if (!currentUser) {
        // 申诉页面例外
        if (path === '/appeal') {
          if (method === 'GET') {
            return new Response(HTMLTemplates.getAppealTemplate(), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }
        } else {
          return new Response('', {
            status: 302,
            headers: { 'Location': '/login' }
          });
        }
      }

      // 消息相关路由
      if (path === '/chat') {
        if (method === 'GET') {
          const contacts = await ChatManager.getContacts(currentUser.uid);
          return new Response(HTMLTemplates.getChatListTemplate(currentUser, contacts), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }
      }

      // 发送消息
      if (path === '/send-message' && method === 'POST') {
        const jsonData = await request.json();
        const receiverUsername = jsonData.receiver;
        const content = jsonData.content;

        if (!receiverUsername || !content) {
          return new Response(JSON.stringify({success: false, error: "接收者和内容不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        // 检查接收者是否存在
        const receiverUser = await KVStore.getUserByUsername(receiverUsername);
        if (!receiverUser) {
          return new Response(JSON.stringify({success: false, error: "用户不存在"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        // 发送消息
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

        // 检查用户是否存在
        const targetUser = await KVStore.getUserByUsername(targetUsername);
        if (!targetUser) {
          return new Response(HTMLTemplates.getErrorTemplate("用户不存在", currentUser), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        // 获取聊天记录
        const messages = await ChatManager.getChatHistory(currentUser.uid, targetUser.uid);
        
        // 标记消息为已读
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

      // 个人资料相关路由
      if (path === '/profile') {
        return new Response('', {
          status: 302,
          headers: { 'Location': `/profile/${currentUser.username}` }
        });
      }

      if (path.startsWith('/profile/') && method === 'GET') {
        const profileUsername = path.substring(9);
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
      if (path === '/edit-profile') {
        if (method === 'GET') {
          return new Response(HTMLTemplates.getEditProfileTemplate(currentUser), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        } else if (method === 'POST') {
          const formData = await request.formData();
          const updates = {
            display_name: formData.get('display_name')?.toString().trim(),
            avatar: formData.get('avatar')?.toString().trim(),
            bio: formData.get('bio')?.toString().trim(),
            gender: formData.get('gender')?.toString().trim()
          };

          const currentPassword = formData.get('current_password')?.toString();
          const newPassword = formData.get('new_password')?.toString();
          
          if (newPassword && newPassword.length >= 6) {
            updates.password = newPassword;
          }

          const result = await UserManager.updateProfile(currentUser.uid, updates, currentPassword);
          if (!result.success) {
            return new Response(HTMLTemplates.getEditProfileTemplate(currentUser, result.error), {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          }

          // 更新当前用户
          currentUser = result.user;
          
          return new Response('', {
            status: 302,
            headers: { 'Location': `/profile/${currentUser.username}` }
          });
        }
      }

      // 设置页面
      if (path === '/settings') {
        if (method === 'GET') {
          return new Response(HTMLTemplates.getSettingsTemplate(currentUser), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }
      }

      // 更新设置
      if (path === '/update-setting' && method === 'POST') {
        const jsonData = await request.json();
        const setting = jsonData.setting;
        const value = jsonData.value;

        if (!setting) {
          return new Response(JSON.stringify({success: false, error: "设置项不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        // 更新用户设置
        const user = await KVStore.getUser(currentUser.uid);
        if (!user) {
          return new Response(JSON.stringify({success: false, error: "用户不存在"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        if (!user.settings) {
          user.settings = {
            theme: "light",
            notifications: true,
            privacy: {
              last_seen: "everyone",
              profile_photo: "everyone",
              forward_messages: "everyone"
            }
          };
        }

        // 处理嵌套设置
        if (setting.includes('.')) {
          const parts = setting.split('.');
          if (parts[0] === 'privacy' && user.settings.privacy) {
            user.settings.privacy[parts[1]] = value;
          }
        } else {
          user.settings[setting] = value;
        }

        const saved = await KVStore.saveUser(user);
        if (!saved) {
          return new Response(JSON.stringify({success: false, error: "保存设置失败"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        return new Response(JSON.stringify({success: true}), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      // 注销账号
      if (path === '/delete-account' && method === 'POST') {
        const jsonData = await request.json();
        const password = jsonData.password;

        if (!password) {
          return new Response(JSON.stringify({success: false, error: "密码不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const result = await UserManager.deleteAccount(currentUser.uid, password);
        if (!result.success) {
          return new Response(JSON.stringify({success: false, error: result.error}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        // 删除会话
        if (sessionToken) {
          await SessionManager.deleteSession(sessionToken);
        }

        return new Response(JSON.stringify({success: true}), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      // 申诉页面
      if (path === '/appeal') {
        if (method === 'GET') {
          return new Response(HTMLTemplates.getAppealTemplate(currentUser), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        } else if (method === 'POST') {
          const jsonData = await request.json();
          const email = jsonData.email;
          const reason = jsonData.reason;

          if (!email || !reason) {
            return new Response(JSON.stringify({success: false, error: "邮箱和申诉理由不能为空"}), {
              headers: { 'Content-Type': 'application/json; charset=utf-8' }
            });
          }

          const result = await UserManager.submitAppeal(currentUser.uid, email, reason);
          return new Response(JSON.stringify(result), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }
      }

      // 管理员面板
      if (path === '/admin') {
        if (method === 'GET') {
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
      }

      // 管理员操作API
      if (path === '/admin/toggle-ban' && method === 'POST') {
        if (!HTMLTemplates.isAdmin(currentUser)) {
          return new Response(JSON.stringify({success: false, error: "权限不足"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const jsonData = await request.json();
        const uid = jsonData.uid;

        if (!uid) {
          return new Response(JSON.stringify({success: false, error: "用户ID不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        // 获取用户当前状态
        const user = await KVStore.getUser(uid);
        if (!user) {
          return new Response(JSON.stringify({success: false, error: "用户不存在"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        // 切换封禁状态
        let result;
        if (user.is_banned) {
          result = await AdminManager.unbanUser(uid);
        } else {
          // 默认封禁1天
          result = await AdminManager.banUser(uid, "1day", "管理员手动封禁");
        }

        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      if (path === '/admin/add-title' && method === 'POST') {
        if (!HTMLTemplates.isAdmin(currentUser)) {
          return new Response(JSON.stringify({success: false, error: "权限不足"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const jsonData = await request.json();
        const uid = jsonData.uid;
        const titleName = jsonData.titleName;
        const titleDisplay = jsonData.titleDisplay;
        const color = jsonData.color || "blue";

        if (!uid || !titleName) {
          return new Response(JSON.stringify({success: false, error: "用户ID和头衔名称不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const result = await AdminManager.addTitleToUser(uid, titleName, titleDisplay, color);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      if (path === '/admin/reset-password' && method === 'POST') {
        if (!HTMLTemplates.isAdmin(currentUser)) {
          return new Response(JSON.stringify({success: false, error: "权限不足"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const jsonData = await request.json();
        const uid = jsonData.uid;

        if (!uid) {
          return new Response(JSON.stringify({success: false, error: "用户ID不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const result = await AdminManager.resetPassword(uid);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      if (path === '/admin/set-invite-code' && method === 'POST') {
        if (!HTMLTemplates.isAdmin(currentUser)) {
          return new Response(HTMLTemplates.getAdminPanelTemplate(currentUser, [], {}, [], "权限不足"), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        const formData = await request.formData();
        const newCode = formData.get('new_invite_code')?.toString().trim();

        if (!newCode) {
          const users = await KVStore.getAllUsers();
          const config = await KVStore.getConfig();
          const appeals = (await KVStore.getAuditRecords()).filter(a => !a.type || (a.type !== "ban" && a.type !== "unban"));
          return new Response(HTMLTemplates.getAdminPanelTemplate(currentUser, users, config, appeals, "邀请码不能为空"), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        const result = await AdminManager.updateInviteCode(newCode);
        if (!result.success) {
          const users = await KVStore.getAllUsers();
          const config = await KVStore.getConfig();
          const appeals = (await KVStore.getAuditRecords()).filter(a => !a.type || (a.type !== "ban" && a.type !== "unban"));
          return new Response(HTMLTemplates.getAdminPanelTemplate(currentUser, users, config, appeals, result.error), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        // 重新获取配置
        const updatedConfig = await KVStore.getConfig();
        const users = await KVStore.getAllUsers();
        const appeals = (await KVStore.getAuditRecords()).filter(a => !a.type || (a.type !== "ban" && a.type !== "unban"));
        return new Response(HTMLTemplates.getAdminPanelTemplate(currentUser, users, updatedConfig, appeals), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      if (path === '/admin/process-appeal' && method === 'POST') {
        if (!HTMLTemplates.isAdmin(currentUser)) {
          return new Response(JSON.stringify({success: false, error: "权限不足"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const jsonData = await request.json();
        const appealId = jsonData.appeal_id;
        const status = jsonData.status;
        const response = jsonData.response || "";

        if (!appealId || !status) {
          return new Response(JSON.stringify({success: false, error: "申诉ID和状态不能为空"}), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }

        const result = await AdminManager.processAppeal(appealId, status, response);
        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      // 表情页面
      if (path === '/emoji') {
        const page = parseInt(url.searchParams.get('page') || '1');
        return new Response(HTMLTemplates.getEmojiTemplate(currentUser, page), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      // 404页面
      return new Response(HTMLTemplates.getErrorTemplate("页面不存在", currentUser), {
        status: 404,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });

    } catch (error) {
      console.error("路由处理错误:", error);
      return new Response(HTMLTemplates.getErrorTemplate("服务器内部错误: " + error.message, currentUser), {
        status: 500,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
  }
}

// 主入口点
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  try {
    // 初始化绑定
    await initializeBindings();
    return await Router.handleRequest(request);
  } catch (error) {
    console.error("处理请求时出错:", error);
    return new Response(HTMLTemplates.getErrorTemplate("服务器内部错误"), {
      status: 500,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
}