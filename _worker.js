let BOT_TOKEN;
let GROUP_ID;
let MAX_MESSAGES_PER_MINUTE;
let SECRET_TOKEN;

let lastCleanupTime = 0;
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 小时
let isInitialized = false;
const processedMessages = new Set();
const processedCallbacks = new Set();

// 全局并发锁管理
const globalLocks = new Map(); // key -> Promise

// 批量写入队列和管理
const pendingDbWrites = new Map();
const batchWriteQueue = new Map(); // 延迟写入队列
let lastDbFlush = 0;
const DB_FLUSH_INTERVAL = 5000; // 5秒批量写入
const DELAYED_WRITE_TIMEOUT = 2000; // 2秒延迟写入

const settingsCache = new Map([
  ['verification_enabled', null],
  ['user_raw_enabled', null]
]);

// --- Enhanced LRU Cache Implementation ---
class LRUCache {
  constructor(maxSize) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }
  
  get(key) {
    const value = this.cache.get(key);
    if (value !== undefined) {
      // 移到最后以维持LRU顺序
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }
  
  set(key, value) {
    // 如果已存在，先删除再重新添加到最后
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // 删除最旧的项
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }
  
  clear() {
    this.cache.clear();
  }
  
  delete(key) {
    return this.cache.delete(key);
  }
}

const userInfoCache = new LRUCache(1000);
const topicIdCache = new LRUCache(1000);
const userStateCache = new LRUCache(1000);
const messageRateCache = new LRUCache(1000);

// --- Global Lock Manager ---
async function withLock(key, fn) {
  // 如果已经有锁在运行，等待它完成
  if (globalLocks.has(key)) {
    await globalLocks.get(key);
  }
  
  // 创建新的锁
  const promise = (async () => {
    try {
      return await fn();
    } finally {
      globalLocks.delete(key);
    }
  })();
  
  globalLocks.set(key, promise);
  return await promise;
}

// --- Crypto Utils ---
async function createHmac(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyHmac(message, signature, secret) {
  const expectedSignature = await createHmac(message, secret);
  return expectedSignature === signature;
}

// --- Enhanced Database Operations ---
async function scheduleDelayedWrite(key, writePromise, delay = DELAYED_WRITE_TIMEOUT) {
  // 清除之前的延迟写入
  if (batchWriteQueue.has(key)) {
    clearTimeout(batchWriteQueue.get(key).timeout);
  }
  
  const timeout = setTimeout(async () => {
    try {
      await writePromise();
      batchWriteQueue.delete(key);
    } catch (error) {
      console.error(`[SYSTEM] 延迟写入失败 [${key}]:`, error.message);
      batchWriteQueue.delete(key);
    }
  }, delay);
  
  batchWriteQueue.set(key, { writePromise, timeout });
}

async function flushPendingDbWrites(d1) {
  if (pendingDbWrites.size === 0) return;
  
  const writes = Array.from(pendingDbWrites.values());
  pendingDbWrites.clear();
  
  try {
    await d1.batch(writes);
  } catch (error) {
    console.error(`[SYSTEM] 批量DB写入失败: ${error.message}`);
  }
}

async function flushAllDelayedWrites() {
  const promises = [];
  for (const [key, { writePromise, timeout }] of batchWriteQueue.entries()) {
    clearTimeout(timeout);
    promises.push(writePromise().catch(error => 
      console.error(`[SYSTEM] 强制flush延迟写入失败 [${key}]:`, error.message)
    ));
  }
  batchWriteQueue.clear();
  await Promise.all(promises);
}

// --- Enhanced Telegram API Wrapper ---
async function telegramApi(method, payload, retries = 3) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/${method}`;
  
  for (let i = 0; i < retries; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000); // 增加超时时间
      
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      const data = await response.json();
      
      if (response.ok) {
        return data;
      }
      
      // 错误处理
      if (response.status === 429) {
        // 正确处理Telegram API的429错误
        const retryAfter = parseInt(response.headers.get('Retry-After') || '5');
        console.warn(`[SYSTEM] Telegram API限流 [${method}], 等待 ${retryAfter} 秒`);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      
      if (response.status === 403) {
        // 用户屏蔽或bot被踢
        if (payload.chat_id && payload.chat_id !== GROUP_ID) {
          console.warn(`[USER] 用户 ${payload.chat_id} 屏蔽了bot或bot被踢出`);
        } else {
          console.error(`[SYSTEM] bot在群组中权限不足: ${data.description}`);
        }
      }
      
      if (response.status === 400) {
        console.error(`[USER] Telegram API参数错误 [${method}]:`, {
          description: data.description,
          payload: payload
        });
      }
      
      // 其他错误
      console.error(`[SYSTEM] Telegram API错误 [${method}]:`, {
        status: response.status,
        description: data.description,
        payload: payload
      });
      
      throw new Error(`Telegram API错误: ${data.description || '未知错误'}`);
      
    } catch (error) {
      if (error.name === 'AbortError') {
        console.error(`[SYSTEM] Telegram API超时 [${method}] (尝试 ${i + 1}/${retries})`);
      } else {
        console.error(`[SYSTEM] Telegram API请求失败 [${method}] (尝试 ${i + 1}/${retries}):`, error.message);
      }
      
      if (i === retries - 1) {
        throw error;
      }
      
      // 指数退避，但最大不超过5秒
      const delay = Math.min(1000 * Math.pow(2, i), 5000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// --- Enhanced User State Management ---
async function getOrInitUserState(chatId, d1) {
  let userState = userStateCache.get(chatId);
  if (userState !== undefined) {
    return userState;
  }
  
  userState = await d1.prepare('SELECT * FROM user_states WHERE chat_id = ?')
    .bind(chatId)
    .first();
    
  if (!userState) {
    userState = {
      chat_id: chatId,
      is_blocked: false,
      is_first_verification: true,
      is_verified: false,
      verified_expiry: null,
      verification_code: null,
      code_expiry: null,
      last_verification_message_id: null,
      is_rate_limited: false,
      is_verifying: false
    };
    
    try {
      await d1.prepare(`
        INSERT INTO user_states (
          chat_id, is_blocked, is_first_verification, is_verified, 
          verified_expiry, verification_code, code_expiry, 
          last_verification_message_id, is_rate_limited, is_verifying
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        chatId, false, true, false, null, null, null, null, false, false
      ).run();
    } catch (error) {
      console.error(`[SYSTEM] 初始化用户状态失败 [${chatId}]:`, error.message);
      // 继续使用内存中的状态
    }
  }
  
  userStateCache.set(chatId, userState);
  return userState;
}

async function updateUserState(chatId, partial, d1, immediate = false) {
  let userState = userStateCache.get(chatId);
  if (!userState) {
    userState = await getOrInitUserState(chatId, d1);
  }
  
  // 更新缓存
  Object.assign(userState, partial);
  userStateCache.set(chatId, userState);
  
  // 构建更新SQL
  const keys = Object.keys(partial);
  const setClause = keys.map(key => `${key} = ?`).join(', ');
  const values = keys.map(key => partial[key]);
  
  const writeKey = `user_state_${chatId}`;
  const writePromise = () => d1.prepare(`UPDATE user_states SET ${setClause} WHERE chat_id = ?`)
    .bind(...values, chatId)
    .run();
  
  if (immediate) {
    // 立即写入（用于重要状态变更）
    try {
      await writePromise();
    } catch (error) {
      console.error(`[SYSTEM] 立即更新用户状态失败 [${chatId}]:`, error.message);
    }
  } else {
    // 延迟写入（用于频繁更新）
    scheduleDelayedWrite(writeKey, writePromise);
  }
}

// --- Enhanced Verification Logic ---
async function resetVerification(chatId, d1) {
  return await withLock(`verification_${chatId}`, async () => {
    try {
      const userState = await getOrInitUserState(chatId, d1);
      
      // 删除旧的验证消息（允许失败）
      if (userState.last_verification_message_id) {
        try {
          await telegramApi('deleteMessage', {
            chat_id: chatId,
            message_id: userState.last_verification_message_id
          });
        } catch (deleteError) {
          // 删除失败不影响流程，只记录日志
          console.warn(`[USER] 删除旧验证消息失败 [${chatId}]:`, deleteError.message);
        }
      }
      
      // 重置验证状态（立即写入）
      await updateUserState(chatId, {
        verification_code: null,
        code_expiry: null,
        last_verification_message_id: null,
        is_verifying: false
      }, d1, true);
      
      // 发送新验证码
      await sendVerification(chatId, d1);
      
    } catch (error) {
      console.error(`[SYSTEM] 重置验证失败 [${chatId}]:`, error.message);
      throw error;
    }
  });
}

async function sendVerification(chatId, d1) {
  try {
    const num1 = Math.floor(Math.random() * 10);
    const num2 = Math.floor(Math.random() * 10);
    const operation = Math.random() > 0.5 ? '+' : '-';
    const correctResult = operation === '+' ? num1 + num2 : num1 - num2;

    const options = new Set([correctResult]);
    while (options.size < 4) {
      const wrongResult = correctResult + Math.floor(Math.random() * 5) - 2;
      if (wrongResult !== correctResult) options.add(wrongResult);
    }
    const optionArray = Array.from(options).sort(() => Math.random() - 0.5);

    // 生成带签名的callback_data（如果配置了SECRET_TOKEN）
    const buttons = optionArray.map(option => {
      const isCorrect = option === correctResult;
      const data = `verify_${chatId}_${option}_${isCorrect ? 'correct' : 'wrong'}`;
      let callback_data = data;
      
      if (SECRET_TOKEN && crypto.subtle) {
        try {
          const signature = crypto.createHash ? crypto.createHash('sha256').update(data + SECRET_TOKEN).digest('hex').substring(0, 8) : 'nosig';
          callback_data = `${data}_${signature}`;
        } catch (error) {
          console.warn(`[SYSTEM] 生成callback签名失败:`, error.message);
        }
      }
      
      return {
        text: `(${option})`,
        callback_data: callback_data
      };
    });

    const question = `请计算：${num1} ${operation} ${num2} = ?（点击下方按钮完成验证）`;
    const nowSeconds = Math.floor(Date.now() / 1000);
    const codeExpiry = nowSeconds + 300; // 5分钟有效期

    const response = await telegramApi('sendMessage', {
      chat_id: chatId,
      text: question,
      reply_markup: { inline_keyboard: [buttons] }
    });

    // 立即更新验证状态
    await updateUserState(chatId, {
      verification_code: correctResult.toString(),
      code_expiry: codeExpiry,
      last_verification_message_id: response.result.message_id.toString(),
      is_verifying: true
    }, d1, true);

  } catch (error) {
    console.error(`[SYSTEM] 发送验证码失败 [${chatId}]:`, error.message);
    // 重置验证状态以防卡住
    await updateUserState(chatId, { is_verifying: false }, d1, true);
    throw error;
  }
}

async function handleVerification(chatId, messageId, d1) {
  return await withLock(`verification_${chatId}`, async () => {
    try {
      const userState = await getOrInitUserState(chatId, d1);
      
      // 如果用户已经在验证中，避免重复发送
      if (userState.is_verifying) {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const isCodeValid = userState.verification_code && 
                           userState.code_expiry && 
                           nowSeconds < userState.code_expiry;
        
        if (isCodeValid) {
          // 验证码仍然有效，不重复发送
          return;
        }
      }
      
      // 删除旧的验证消息（允许失败）
      if (userState.last_verification_message_id) {
        try {
          await telegramApi('deleteMessage', {
            chat_id: chatId,
            message_id: userState.last_verification_message_id
          });
        } catch (deleteError) {
          console.warn(`[USER] 删除上一条验证消息失败 [${chatId}]:`, deleteError.message);
        }
      }
      
      // 重置并发送新验证码
      await updateUserState(chatId, {
        verification_code: null,
        code_expiry: null,
        last_verification_message_id: null,
        is_verifying: true
      }, d1, true);

      await sendVerification(chatId, d1);
      
    } catch (error) {
      console.error(`[SYSTEM] 处理验证过程失败 [${chatId}]:`, error.message);
      
      try {
        await updateUserState(chatId, { is_verifying: false }, d1, true);
      } catch (resetError) {
        console.error(`[SYSTEM] 重置用户验证状态失败 [${chatId}]:`, resetError.message);
      }
      
      throw error;
    }
  });
}

// --- Enhanced Rate Limiting ---
async function updateMessageRate(chatId, d1, isStartCommand = false) {
  const now = Date.now();
  const window = isStartCommand ? 5 * 60 * 1000 : 60 * 1000; // start命令5分钟窗口，普通消息1分钟窗口

  let data = messageRateCache.get(chatId);
  if (data === undefined) {
    const dbData = await d1.prepare('SELECT * FROM message_rates WHERE chat_id = ?')
      .bind(chatId)
      .first();
    if (!dbData) {
      data = { 
        message_count: 0, 
        window_start: now,
        start_count: 0,
        start_window_start: now
      };
      // 初始化数据库记录
      try {
        await d1.prepare('INSERT INTO message_rates (chat_id, message_count, window_start, start_count, start_window_start) VALUES (?, ?, ?, ?, ?)')
          .bind(chatId, 0, now, 0, now)
          .run();
      } catch (error) {
        console.error(`[SYSTEM] 初始化消息速率记录失败 [${chatId}]:`, error.message);
      }
    } else {
      data = dbData;
    }
    messageRateCache.set(chatId, data);
  }

  if (isStartCommand) {
    if (now - data.start_window_start > window) {
      data.start_count = 1;
      data.start_window_start = now;
    } else {
      data.start_count += 1;
    }
  } else {
    if (now - data.window_start > window) {
      data.message_count = 1;
      data.window_start = now;
    } else {
      data.message_count += 1;
    }
  }

  messageRateCache.set(chatId, data);
  
  // 延迟写入DB
  const writeKey = `message_rate_${chatId}`;
  const writePromise = () => d1.prepare(`
    UPDATE message_rates 
    SET message_count = ?, window_start = ?, start_count = ?, start_window_start = ? 
    WHERE chat_id = ?
  `).bind(data.message_count, data.window_start, data.start_count, data.start_window_start, chatId).run();
  
  scheduleDelayedWrite(writeKey, writePromise);
  
  return data;
}

async function checkMessageRate(chatId, d1) {
  const data = await updateMessageRate(chatId, d1, false);
  return data.message_count > MAX_MESSAGES_PER_MINUTE;
}

async function checkStartCommandRate(chatId, d1) {
  const data = await updateMessageRate(chatId, d1, true);
  return data.start_count > 1; // 5分钟内最多1次start命令
}

// --- Settings Management ---
async function getSetting(key, d1) {
  const result = await d1.prepare('SELECT value FROM settings WHERE key = ?')
    .bind(key)
    .first();
  return result?.value || null;
}

async function setSetting(key, value, d1) {
  await d1.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
    .bind(key, value)
    .run();
    
  if (key === 'verification_enabled') {
    settingsCache.set('verification_enabled', value === 'true');
    if (value === 'false') {
      const nowSeconds = Math.floor(Date.now() / 1000);
      const verifiedExpiry = nowSeconds + 3600 * 24;
      await d1.prepare('UPDATE user_states SET is_verified = ?, verified_expiry = ?, is_verifying = ?, verification_code = NULL, code_expiry = NULL, is_first_verification = ? WHERE chat_id NOT IN (SELECT chat_id FROM user_states WHERE is_blocked = TRUE)')
        .bind(true, verifiedExpiry, false, false)
        .run();
      userStateCache.clear();
    }
  } else if (key === 'user_raw_enabled') {
    settingsCache.set('user_raw_enabled', value === 'true');
  }
}

// --- User Info Management ---
async function getUserInfo(chatId) {
  let userInfo = userInfoCache.get(chatId);
  if (userInfo !== undefined) {
    return userInfo;
  }

  try {
    const data = await telegramApi('getChat', { chat_id: chatId });
    const result = data.result;
    const nickname = result.first_name
      ? `${result.first_name}${result.last_name ? ` ${result.last_name}` : ''}`.trim()
      : result.username || `User_${chatId}`;
    userInfo = {
      id: result.id || chatId,
      username: result.username || `User_${chatId}`,
      nickname: nickname
    };
  } catch (error) {
    console.warn(`[USER] 获取用户信息失败 [${chatId}]:`, error.message);
    userInfo = {
      id: chatId,
      username: `User_${chatId}`,
      nickname: `User_${chatId}`
    };
  }

  userInfoCache.set(chatId, userInfo);
  return userInfo;
}

// --- Enhanced Topic Management ---
async function getExistingTopicId(chatId, d1) {
  let topicId = topicIdCache.get(chatId);
  if (topicId !== undefined) {
    return topicId;
  }

  const result = await d1.prepare('SELECT topic_id FROM chat_topic_mappings WHERE chat_id = ?')
    .bind(chatId)
    .first();
  topicId = result?.topic_id || null;
  if (topicId) {
    topicIdCache.set(chatId, topicId);
  }
  return topicId;
}

async function createForumTopic(topicName, userName, nickname, userId, d1) {
  const data = await telegramApi('createForumTopic', { 
    chat_id: GROUP_ID, 
    name: `${nickname}` 
  });
  
  const topicId = data.result.message_thread_id;

  const now = new Date();
  const formattedTime = now.toISOString().replace('T', ' ').substring(0, 19);
  const notificationContent = await getNotificationContent();
  const pinnedMessage = `昵称: ${nickname}\n用户名: @${userName}\nUserID: ${userId}\n发起时间: ${formattedTime}\n\n${notificationContent}`;
  
  try {
    const messageResponse = await telegramApi('sendMessage', {
      chat_id: GROUP_ID,
      text: pinnedMessage,
      message_thread_id: topicId
    });
    
    const messageId = messageResponse.result.message_id;
    await telegramApi('pinChatMessage', {
      chat_id: GROUP_ID,
      message_id: messageId,
      message_thread_id: topicId
    });
  } catch (error) {
    console.warn(`[SYSTEM] 发送或置顶topic欢迎消息失败 [${topicId}]:`, error.message);
    // 不影响topic创建流程
  }

  return topicId;
}

async function saveTopicId(chatId, topicId, d1) {
  await d1.prepare('INSERT OR REPLACE INTO chat_topic_mappings (chat_id, topic_id) VALUES (?, ?)')
    .bind(chatId, topicId)
    .run();
  topicIdCache.set(chatId, topicId);
}

async function getPrivateChatId(topicId, d1) {
  // 先从缓存查找
  for (const [chatId, tid] of topicIdCache.cache) {
    if (tid === topicId) return chatId;
  }
  
  // 再从数据库查找
  const mapping = await d1.prepare('SELECT chat_id FROM chat_topic_mappings WHERE topic_id = ?')
    .bind(topicId)
    .first();
  return mapping?.chat_id || null;
}

async function ensureUserTopic(chatId, userInfo, d1) {
  // 使用全局锁确保同一用户的topic创建是串行的
  return await withLock(`topic_creation_${chatId}`, async () => {
    try {
      // 再次检查是否已存在（防止并发创建）
      let topicId = await getExistingTopicId(chatId, d1);
      if (topicId) {
        return topicId;
      }

      const userName = userInfo.username || `User_${chatId}`;
      const nickname = userInfo.nickname || userName;
      
      console.log(`[SYSTEM] 为用户创建新topic [${chatId}]: ${nickname}`);
      
      topicId = await createForumTopic(nickname, userName, nickname, userInfo.id || chatId, d1);
      await saveTopicId(chatId, topicId, d1);
      
      return topicId;
      
    } catch (error) {
      console.error(`[SYSTEM] 创建用户topic失败 [${chatId}]:`, error.message);
      throw error;
    }
  });
}

async function validateTopic(topicId) {
  try {
    const data = await telegramApi('sendMessage', {
      chat_id: GROUP_ID,
      message_thread_id: topicId,
      text: "验证topic",
      disable_notification: true
    });
    
    if (data.ok) {
      // 立即删除验证消息
      try {
        await telegramApi('deleteMessage', {
          chat_id: GROUP_ID,
          message_id: data.result.message_id
        });
      } catch (deleteError) {
        console.warn(`[SYSTEM] 删除topic验证消息失败:`, deleteError.message);
      }
      return true;
    }
    return false;
  } catch (error) {
    console.warn(`[SYSTEM] 验证topic失败:`, error.message);
    return false;
  }
}

// --- Message Handling ---
async function sendMessageToTopic(topicId, text) {
  if (!text.trim()) {
    throw new Error('Message text is empty');
  }

  return await telegramApi('sendMessage', {
    chat_id: GROUP_ID,
    text: text,
    message_thread_id: topicId
  });
}

async function copyMessageToTopic(topicId, message) {
  return await telegramApi('copyMessage', {
    chat_id: GROUP_ID,
    from_chat_id: message.chat.id,
    message_id: message.message_id,
    message_thread_id: topicId,
    disable_notification: true
  });
}

async function forwardMessageToPrivateChat(privateChatId, message) {
  return await telegramApi('copyMessage', {
    chat_id: privateChatId,
    from_chat_id: message.chat.id,
    message_id: message.message_id,
    disable_notification: true
  });
}

async function sendMessageToUser(chatId, text) {
  return await telegramApi('sendMessage', { 
    chat_id: chatId, 
    text: text 
  });
}

// --- Admin Functions ---
async function checkIfAdmin(userId) {
  try {
    const data = await telegramApi('getChatMember', {
      chat_id: GROUP_ID,
      user_id: userId
    });
    return data.ok && (data.result.status === 'administrator' || data.result.status === 'creator');
  } catch (error) {
    console.error(`[SYSTEM] 检查管理员权限失败 [${userId}]:`, error.message);
    return false;
  }
}

async function sendAdminPanel(chatId, topicId, privateChatId, messageId, d1) {
  const verificationEnabled = (await getSetting('verification_enabled', d1)) === 'true';
  const userRawEnabled = (await getSetting('user_raw_enabled', d1)) === 'true';

  const buttons = [
    [
      { text: '拉黑用户', callback_data: `block_${privateChatId}` },
      { text: '解除拉黑', callback_data: `unblock_${privateChatId}` }
    ],
    [
      { text: verificationEnabled ? '关闭验证码' : '开启验证码', callback_data: `toggle_verification_${privateChatId}` },
      { text: '查询黑名单', callback_data: `check_blocklist_${privateChatId}` }
    ],
    [
      { text: userRawEnabled ? '关闭用户Raw' : '开启用户Raw', callback_data: `toggle_user_raw_${privateChatId}` },
      { text: 'GitHub项目', url: 'https://github.com/iawooo/ctt' }
    ],
    [
      { text: '删除用户', callback_data: `delete_user_${privateChatId}` }
    ]
  ];

  const adminMessage = '管理员面板：请选择操作';
  
  try {
    await Promise.all([
      telegramApi('sendMessage', {
        chat_id: chatId,
        message_thread_id: topicId,
        text: adminMessage,
        reply_markup: { inline_keyboard: buttons }
      }),
      telegramApi('deleteMessage', {
        chat_id: chatId,
        message_id: messageId
      }).catch(error => {
        console.warn(`[USER] 删除管理员命令消息失败:`, error.message);
      })
    ]);
  } catch (error) {
    console.error(`[SYSTEM] 发送管理员面板失败:`, error.message);
  }
}

// --- Content Fetchers ---
async function getVerificationSuccessMessage(d1) {
  const userRawEnabled = (await getSetting('user_raw_enabled', d1)) === 'true';
  if (!userRawEnabled) return '验证成功！您现在可以与我聊天。';

  try {
    const response = await fetch('https://raw.githubusercontent.com/iawooo/ctt/refs/heads/main/CFTeleTrans/start.md');
    if (!response.ok) return '验证成功！您现在可以与我聊天。';
    const message = await response.text();
    return message.trim() || '验证成功！您现在可以与我聊天。';
  } catch (error) {
    console.warn(`[SYSTEM] 获取验证成功消息失败:`, error.message);
    return '验证成功！您现在可以与我聊天。';
  }
}

async function getNotificationContent() {
  try {
    const response = await fetch('https://raw.githubusercontent.com/iawooo/ctt/refs/heads/main/CFTeleTrans/notification.md');
    if (!response.ok) return '';
    const content = await response.text();
    return content.trim() || '';
  } catch (error) {
    console.warn(`[SYSTEM] 获取通知内容失败:`, error.message);
    return '';
  }
}

// --- Database Setup ---
async function checkAndRepairTables(d1) {
  const expectedTables = {
    user_states: {
      columns: {
        chat_id: 'TEXT PRIMARY KEY',
        is_blocked: 'BOOLEAN DEFAULT FALSE',
        is_verified: 'BOOLEAN DEFAULT FALSE',
        verified_expiry: 'INTEGER',
        verification_code: 'TEXT',
        code_expiry: 'INTEGER',
        last_verification_message_id: 'TEXT',
        is_first_verification: 'BOOLEAN DEFAULT TRUE',
        is_rate_limited: 'BOOLEAN DEFAULT FALSE',
        is_verifying: 'BOOLEAN DEFAULT FALSE'
      }
    },
    message_rates: {
      columns: {
        chat_id: 'TEXT PRIMARY KEY',
        message_count: 'INTEGER DEFAULT 0',
        window_start: 'INTEGER',
        start_count: 'INTEGER DEFAULT 0',
        start_window_start: 'INTEGER'
      }
    },
    chat_topic_mappings: {
      columns: {
        chat_id: 'TEXT PRIMARY KEY',
        topic_id: 'TEXT NOT NULL'
      }
    },
    settings: {
      columns: {
        key: 'TEXT PRIMARY KEY',
        value: 'TEXT'
      }
    }
  };

  for (const [tableName, structure] of Object.entries(expectedTables)) {
    const tableInfo = await d1.prepare(
      `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`
    ).bind(tableName).first();

    if (!tableInfo) {
      await createTable(d1, tableName, structure);
      continue;
    }

    const columnsResult = await d1.prepare(
      `PRAGMA table_info(${tableName})`
    ).all();
    
    const currentColumns = new Map(
      columnsResult.results.map(col => [col.name, {
        type: col.type,
        notnull: col.notnull,
        dflt_value: col.dflt_value
      }])
    );

    for (const [colName, colDef] of Object.entries(structure.columns)) {
      if (!currentColumns.has(colName)) {
        const columnParts = colDef.split(' ');
        const addColumnSQL = `ALTER TABLE ${tableName} ADD COLUMN ${colName} ${columnParts.slice(1).join(' ')}`;
        await d1.exec(addColumnSQL);
      }
    }

    if (tableName === 'settings') {
      await d1.exec('CREATE INDEX IF NOT EXISTS idx_settings_key ON settings (key)');
    }
  }

  await Promise.all([
    d1.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)')
      .bind('verification_enabled', 'true').run(),
    d1.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)')
      .bind('user_raw_enabled', 'true').run()
  ]);

  settingsCache.set('verification_enabled', (await getSetting('verification_enabled', d1)) === 'true');
  settingsCache.set('user_raw_enabled', (await getSetting('user_raw_enabled', d1)) === 'true');
}

async function createTable(d1, tableName, structure) {
  const columnsDef = Object.entries(structure.columns)
    .map(([name, def]) => `${name} ${def}`)
    .join(', ');
  const createSQL = `CREATE TABLE ${tableName} (${columnsDef})`;
  await d1.exec(createSQL);
}

async function cleanExpiredVerificationCodes(d1) {
  const now = Date.now();
  if (now - lastCleanupTime < CLEANUP_INTERVAL) {
    return;
  }

  const nowSeconds = Math.floor(now / 1000);
  const expiredCodes = await d1.prepare(
    'SELECT chat_id FROM user_states WHERE code_expiry IS NOT NULL AND code_expiry < ?'
  ).bind(nowSeconds).all();

  if (expiredCodes.results.length > 0) {
    await d1.batch(
      expiredCodes.results.map(({ chat_id }) =>
        d1.prepare(
          'UPDATE user_states SET verification_code = NULL, code_expiry = NULL, is_verifying = FALSE WHERE chat_id = ?'
        ).bind(chat_id)
      )
    );
    
    // 清理对应的缓存
    expiredCodes.results.forEach(({ chat_id }) => {
      const state = userStateCache.get(chat_id);
      if (state) {
        state.verification_code = null;
        state.code_expiry = null;
        state.is_verifying = false;
        userStateCache.set(chat_id, state);
      }
    });
  }
  lastCleanupTime = now;
}

// --- Bot Initialization ---
async function getBotId() {
  const data = await telegramApi('getMe', {});
  return data.result.id;
}

async function autoRegisterWebhook(request) {
  const webhookUrl = `${new URL(request.url).origin}/webhook`;
  await telegramApi('setWebhook', { url: webhookUrl });
}

async function checkBotPermissions() {
  const data = await telegramApi('getChat', { chat_id: GROUP_ID });
  if (!data.ok) {
    throw new Error(`Failed to access group: ${data.description}`);
  }

  const memberData = await telegramApi('getChatMember', {
    chat_id: GROUP_ID,
    user_id: (await getBotId())
  });
  
  if (!memberData.ok) {
    throw new Error(`Failed to get bot member status: ${memberData.description}`);
  }
}

async function initialize(d1, request) {
  await Promise.all([
    checkAndRepairTables(d1),
    autoRegisterWebhook(request),
    checkBotPermissions(),
    cleanExpiredVerificationCodes(d1)
  ]);
}

// --- Main Message Handlers ---
async function onMessage(message, d1) {
  const chatId = message.chat.id.toString();
  const text = message.text || '';
  const messageId = message.message_id;

  // --- Group Message Handling ---
  if (chatId === GROUP_ID) {
    const topicId = message.message_thread_id;
    if (topicId) {
      const privateChatId = await getPrivateChatId(topicId, d1);
      if (privateChatId && text === '/admin') {
        await sendAdminPanel(chatId, topicId, privateChatId, messageId, d1);
        return;
      }
      if (privateChatId && text.startsWith('/reset_user')) {
        await handleResetUser(chatId, topicId, text, d1);
        return;
      }
      if (privateChatId) {
        await forwardMessageToPrivateChat(privateChatId, message);
      }
    }
    return;
  }

  // --- Private Message Handling ---
  let userState = await getOrInitUserState(chatId, d1);

  if (userState.is_blocked) {
    await sendMessageToUser(chatId, "您已被拉黑，无法发送消息。请联系管理员解除拉黑。");
    return;
  }

  const verificationEnabled = (await getSetting('verification_enabled', d1)) === 'true';

  if (verificationEnabled) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const isVerified = userState.is_verified && userState.verified_expiry && nowSeconds < userState.verified_expiry;
    const isFirstVerification = userState.is_first_verification;
    const isRateLimited = await checkMessageRate(chatId, d1);
    const isVerifying = userState.is_verifying || false;

    if (!isVerified || (isRateLimited && !isFirstVerification)) {
      if (isVerifying) {
        // 检查验证码是否已过期
        const isCodeExpired = !userState.verification_code || !userState.code_expiry || nowSeconds > userState.code_expiry;
        
        if (isCodeExpired) {
          await sendMessageToUser(chatId, '验证码已过期，正在为您发送新的验证码...');
          await resetVerification(chatId, d1);
          return;
        } else {
          await sendMessageToUser(chatId, `请完成验证后发送消息"${text || '您的具体信息'}"。`);
        }
        return;
      }
      await sendMessageToUser(chatId, `请完成验证后发送消息"${text || '您的具体信息'}"。`);
      await handleVerification(chatId, messageId, d1);
      return;
    }
  }

  // --- Handle /start Command ---
  if (text === '/start') {
    if (await checkStartCommandRate(chatId, d1)) {
      await sendMessageToUser(chatId, "您发送 /start 命令过于频繁，请稍后再试！");
      return;
    }

    const successMessage = await getVerificationSuccessMessage(d1);
    await sendMessageToUser(chatId, `${successMessage}\n你好，欢迎使用私聊机器人，现在发送信息吧！`);
    const userInfo = await getUserInfo(chatId);
    await ensureUserTopic(chatId, userInfo, d1);
    return;
  }

  // --- Forward User Message to Topic ---
  const userInfo = await getUserInfo(chatId);
  if (!userInfo) {
    await sendMessageToUser(chatId, "无法获取用户信息，请稍后再试或联系管理员。");
    return;
  }

  let topicId = await ensureUserTopic(chatId, userInfo, d1);
  if (!topicId) {
    await sendMessageToUser(chatId, "无法创建话题，请稍后再试或联系管理员。");
    return;
  }

  const isTopicValid = await validateTopic(topicId);
  if (!isTopicValid) {
    // topic失效，清理缓存并重新创建
    await d1.prepare('DELETE FROM chat_topic_mappings WHERE chat_id = ?').bind(chatId).run();
    topicIdCache.delete(chatId);
    
    topicId = await ensureUserTopic(chatId, userInfo, d1);
    if (!topicId) {
      await sendMessageToUser(chatId, "无法重新创建话题，请稍后再试或联系管理员。");
      return;
    }
  }

  const userName = userInfo.username || `User_${chatId}`;
  const nickname = userInfo.nickname || userName;

  try {
    if (text) {
      const formattedMessage = `${nickname}:\n${text}`;
      await sendMessageToTopic(topicId, formattedMessage);
    } else {
      await copyMessageToTopic(topicId, message);
    }
  } catch (error) {
    console.error(`[SYSTEM] 转发消息到topic失败 [${chatId} -> ${topicId}]:`, error.message);
    await sendMessageToUser(chatId, "消息发送失败，请稍后再试。");
  }
}

async function handleResetUser(chatId, topicId, text, d1) {
  const senderId = chatId;
  const isAdmin = await checkIfAdmin(senderId);
  if (!isAdmin) {
    await sendMessageToTopic(topicId, '只有管理员可以使用此功能。');
    return;
  }

  const parts = text.split(' ');
  if (parts.length !== 2) {
    await sendMessageToTopic(topicId, '用法：/reset_user <chat_id>');
    return;
  }

  const targetChatId = parts[1];
  
  try {
    await d1.batch([
      d1.prepare('DELETE FROM user_states WHERE chat_id = ?').bind(targetChatId),
      d1.prepare('DELETE FROM message_rates WHERE chat_id = ?').bind(targetChatId),
      d1.prepare('DELETE FROM chat_topic_mappings WHERE chat_id = ?').bind(targetChatId)
    ]);
    
    // 清理缓存
    userStateCache.delete(targetChatId);
    messageRateCache.delete(targetChatId);
    topicIdCache.delete(targetChatId);
    
    await sendMessageToTopic(topicId, `用户 ${targetChatId} 的状态已重置。`);
  } catch (error) {
    console.error(`[SYSTEM] 重置用户失败 [${targetChatId}]:`, error.message);
    await sendMessageToTopic(topicId, `重置用户 ${targetChatId} 失败，请检查日志。`);
  }
}

// --- Enhanced Callback Query Handler ---
async function onCallbackQuery(callbackQuery, d1) {
  const chatId = callbackQuery.message.chat.id.toString();
  const topicId = callbackQuery.message.message_thread_id;
  const data = callbackQuery.data;
  const messageId = callbackQuery.message.message_id;
  const callbackKey = `${chatId}:${callbackQuery.id}`;

  // 增强防重机制
  if (processedCallbacks.has(callbackKey)) {
    console.warn(`[USER] 重复的callback query [${callbackKey}]`);
    return;
  }
  processedCallbacks.add(callbackKey);
  
  // 定期清理processedCallbacks
  if (processedCallbacks.size > 10000) {
    processedCallbacks.clear();
  }

  // 验证callback_data签名（如果配置了SECRET_TOKEN）
  if (SECRET_TOKEN) {
    const parts = data.split('_');
    if (parts.length >= 5 && parts[0] === 'verify') {
      const signature = parts[parts.length - 1];
      const dataWithoutSig = parts.slice(0, -1).join('_');
      
      if (crypto.subtle) {
        try {
          const expectedSig = crypto.createHash ? crypto.createHash('sha256').update(dataWithoutSig + SECRET_TOKEN).digest('hex').substring(0, 8) : 'nosig';
          if (signature !== expectedSig && signature !== 'nosig') {
            console.error(`[USER] Invalid callback signature: ${data}`);
            return;
          }
        } catch (error) {
          console.warn(`[SYSTEM] 验证callback签名失败:`, error.message);
        }
      }
    }
  }

  let action;
  let privateChatId;

  if (data.startsWith('verify_')) {
    action = 'verify';
    const parts = data.split('_');
    privateChatId = parts[1];
  } else if (data.startsWith('toggle_verification_')) {
    action = 'toggle_verification';
    privateChatId = data.split('_').slice(2).join('_');
  } else if (data.startsWith('toggle_user_raw_')) {
    action = 'toggle_user_raw';
    privateChatId = data.split('_').slice(3).join('_');
  } else if (data.startsWith('check_blocklist_')) {
    action = 'check_blocklist';
    privateChatId = data.split('_').slice(2).join('_');
  } else if (data.startsWith('block_')) {
    action = 'block';
    privateChatId = data.split('_').slice(1).join('_');
  } else if (data.startsWith('unblock_')) {
    action = 'unblock';
    privateChatId = data.split('_').slice(1).join('_');
  } else if (data.startsWith('delete_user_')) {
    action = 'delete_user';
    privateChatId = data.split('_').slice(2).join('_');
  } else {
    action = data;
    privateChatId = '';
  }

  // --- Enhanced Verification Callback ---
  if (action === 'verify') {
    return await withLock(`verification_${chatId}`, async () => {
      const [, userChatId, selectedAnswer, result] = data.split('_');
      if (userChatId !== chatId) {
        console.warn(`[USER] Callback chatId不匹配: ${userChatId} vs ${chatId}`);
        return;
      }

      let verificationState = await getOrInitUserState(chatId, d1);
      const nowSeconds = Math.floor(Date.now() / 1000);

      // 检查用户是否已经验证通过
      if (verificationState.is_verified && 
          verificationState.verified_expiry && 
          nowSeconds < verificationState.verified_expiry) {
        console.warn(`[USER] 用户 ${chatId} 已验证通过，忽略callback`);
        
        // 删除验证消息
        try {
          await telegramApi('deleteMessage', {
            chat_id: chatId,
            message_id: messageId
          });
        } catch (error) {
          console.warn(`[USER] 删除已验证用户的验证消息失败:`, error.message);
        }
        return;
      }

      const storedCode = verificationState.verification_code;
      const codeExpiry = verificationState.code_expiry;

      // 检查验证码是否过期
      if (!storedCode || (codeExpiry && nowSeconds > codeExpiry)) {
        await sendMessageToUser(chatId, '验证码已过期，正在为您发送新的验证码...');
        
        try {
          await telegramApi('deleteMessage', {
            chat_id: chatId,
            message_id: messageId
          });
        } catch (error) {
          console.warn(`[USER] 删除过期验证按钮失败:`, error.message);
        }
        
        await resetVerification(chatId, d1);
        return;
      }

      // 处理验证结果
      if (result === 'correct') {
        const verifiedExpiry = nowSeconds + 3600 * 24; // 24小时有效期
        
        await updateUserState(chatId, {
          is_verified: true,
          verified_expiry: verifiedExpiry,
          verification_code: null,
          code_expiry: null,
          last_verification_message_id: null,
          is_first_verification: false,
          is_verifying: false
        }, d1, true);

        // 重置消息速率
        const rateData = await updateMessageRate(chatId, d1, false);
        rateData.message_count = 0;
        rateData.window_start = nowSeconds * 1000;
        messageRateCache.set(chatId, rateData);

        const successMessage = await getVerificationSuccessMessage(d1);
        await sendMessageToUser(chatId, `${successMessage}\n你好，欢迎使用私聊机器人！现在可以发送消息了。`);
        
        const userInfo = await getUserInfo(chatId);
        await ensureUserTopic(chatId, userInfo, d1);
        
      } else {
        await sendMessageToUser(chatId, '验证失败，请重新尝试。');
        await handleVerification(chatId, messageId, d1);
      }

      // 删除验证消息
      try {
        await telegramApi('deleteMessage', {
          chat_id: chatId,
          message_id: messageId
        });
      } catch (error) {
        console.warn(`[USER] 删除验证消息失败:`, error.message);
      }
    });
    
  } else {
    // --- Admin Actions ---
    const senderId = callbackQuery.from.id.toString();
    const isAdmin = await checkIfAdmin(senderId);
    if (!isAdmin) {
      await sendMessageToTopic(topicId, '只有管理员可以使用此功能。');
      await sendAdminPanel(chatId, topicId, privateChatId, messageId, d1);
      return;
    }

    try {
      if (action === 'block') {
        await updateUserState(privateChatId, { is_blocked: true }, d1, true);
        await sendMessageToTopic(topicId, `用户 ${privateChatId} 已被拉黑，消息将不再转发。`);
        
      } else if (action === 'unblock') {
        await updateUserState(privateChatId, { 
          is_blocked: false, 
          is_first_verification: true 
        }, d1, true);
        await sendMessageToTopic(topicId, `用户 ${privateChatId} 已解除拉黑，消息将继续转发。`);
        
      } else if (action === 'toggle_verification') {
        const currentState = (await getSetting('verification_enabled', d1)) === 'true';
        const newState = !currentState;
        await setSetting('verification_enabled', newState.toString(), d1);
        await sendMessageToTopic(topicId, `验证码功能已${newState ? '开启' : '关闭'}。`);
        
      } else if (action === 'check_blocklist') {
        const blockedUsers = await d1.prepare('SELECT chat_id FROM user_states WHERE is_blocked = ?')
          .bind(true)
          .all();
        const blockList = blockedUsers.results.length > 0 
          ? blockedUsers.results.map(row => row.chat_id).join('\n')
          : '当前没有被拉黑的用户。';
        await sendMessageToTopic(topicId, `黑名单列表：\n${blockList}`);
        
      } else if (action === 'toggle_user_raw') {
        const currentState = (await getSetting('user_raw_enabled', d1)) === 'true';
        const newState = !currentState;
        await setSetting('user_raw_enabled', newState.toString(), d1);
        await sendMessageToTopic(topicId, `用户端 Raw 链接已${newState ? '开启' : '关闭'}。`);
        
      } else if (action === 'delete_user') {
        userStateCache.delete(privateChatId);
        messageRateCache.delete(privateChatId);
        topicIdCache.delete(privateChatId);
        
        await d1.batch([
          d1.prepare('DELETE FROM user_states WHERE chat_id = ?').bind(privateChatId),
          d1.prepare('DELETE FROM message_rates WHERE chat_id = ?').bind(privateChatId),
          d1.prepare('DELETE FROM chat_topic_mappings WHERE chat_id = ?').bind(privateChatId)
        ]);
        
        await sendMessageToTopic(topicId, `用户 ${privateChatId} 的状态、消息记录和话题映射已删除，用户需重新发起会话。`);
        
      } else {
        await sendMessageToTopic(topicId, `未知操作：${action}`);
      }

      await sendAdminPanel(chatId, topicId, privateChatId, messageId, d1);
      
    } catch (error) {
      console.error(`[SYSTEM] 管理员操作失败 [${action}]:`, error.message);
      await sendMessageToTopic(topicId, `操作失败，请检查日志。`);
    }
  }

  // 回应callback query
  try {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callbackQuery.id
    });
  } catch (error) {
    console.warn(`[SYSTEM] 回应callback query失败:`, error.message);
  }
}

// --- Update Handler ---
async function handleUpdate(update, d1) {
  if (update.message) {
    const messageId = update.message.message_id.toString();
    const chatId = update.message.chat.id.toString();
    const messageKey = `${chatId}:${messageId}`;
    
    if (processedMessages.has(messageKey)) {
      return;
    }
    processedMessages.add(messageKey);
    
    // 定期清理processedMessages
    if (processedMessages.size > 10000) {
      processedMessages.clear();
    }

    await onMessage(update.message, d1);
    
  } else if (update.callback_query) {
    await onCallbackQuery(update.callback_query, d1);
  }
}

// --- Webhook Management ---
async function registerWebhook(request) {
  const webhookUrl = `${new URL(request.url).origin}/webhook`;
  const data = await telegramApi('setWebhook', { url: webhookUrl });
  return new Response(data.ok ? 'Webhook set successfully' : JSON.stringify(data, null, 2));
}

async function unRegisterWebhook() {
  const data = await telegramApi('setWebhook', { url: '' });
  return new Response(data.ok ? 'Webhook removed' : JSON.stringify(data, null, 2));
}

// --- Main Request Handler ---
async function handleRequest(request, env) {
  if (!BOT_TOKEN || !GROUP_ID) {
    return new Response('Server configuration error: Missing required environment variables', { status: 500 });
  }

  const url = new URL(request.url);
  
  if (url.pathname === '/webhook') {
    // 安全校验：检查 X-Telegram-Bot-Api-Secret-Token（如果配置了SECRET_TOKEN）
    if (SECRET_TOKEN) {
      const secretToken = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
      if (secretToken !== SECRET_TOKEN) {
        console.error('[SYSTEM] Invalid secret token in webhook request');
        return new Response('Forbidden', { status: 403 });
      }
    }
    
    try {
      const update = await request.json();
      await handleUpdate(update, env.D1);
      return new Response('OK');
    } catch (error) {
      console.error('[SYSTEM] Webhook处理失败:', error.message);
      return new Response('Bad Request', { status: 400 });
    }
    
  } else if (url.pathname === '/registerWebhook') {
    return await registerWebhook(request);
    
  } else if (url.pathname === '/unRegisterWebhook') {
    return await unRegisterWebhook();
    
  } else if (url.pathname === '/checkTables') {
    await checkAndRepairTables(env.D1);
    return new Response('Database tables checked and repaired', { status: 200 });
    
  } else if (url.pathname === '/flush') {
    // 手动触发flush所有延迟写入
    await flushAllDelayedWrites();
    await flushPendingDbWrites(env.D1);
    return new Response('All pending writes flushed', { status: 200 });
  }
  
  return new Response('Not Found', { status: 404 });
}

// --- Graceful Shutdown Handler ---
async function gracefulShutdown(env) {
  try {
    console.log('[SYSTEM] 开始优雅关闭...');
    await flushAllDelayedWrites();
    await flushPendingDbWrites(env.D1);
    console.log('[SYSTEM] 优雅关闭完成');
  } catch (error) {
    console.error('[SYSTEM] 优雅关闭失败:', error.message);
  }
}

// --- Main Export ---
export default {
  async fetch(request, env) {
    BOT_TOKEN = env.BOT_TOKEN_ENV || null;
    GROUP_ID = env.GROUP_ID_ENV || null;
    SECRET_TOKEN = env.SECRET_TOKEN_ENV || null;
    MAX_MESSAGES_PER_MINUTE = env.MAX_MESSAGES_PER_MINUTE_ENV ? parseInt(env.MAX_MESSAGES_PER_MINUTE_ENV) : 40;

    if (!env.D1) {
      return new Response('Server configuration error: D1 database is not bound', { status: 500 });
    }

    if (!isInitialized) {
      try {
        await initialize(env.D1, request);
        isInitialized = true;
      } catch (error) {
        console.error('[SYSTEM] 初始化失败:', error.message);
        return new Response('Initialization failed', { status: 500 });
      }
    }

    try {
      // 定期flush
      const now = Date.now();
      if (now - lastDbFlush > DB_FLUSH_INTERVAL) {
        flushPendingDbWrites(env.D1).catch(error => 
          console.error('[SYSTEM] 定期flush失败:', error.message)
        );
        lastDbFlush = now;
      }
      
      return await handleRequest(request, env);
    } catch (error) {
      console.error('[SYSTEM] 请求处理失败:', error.message);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};
