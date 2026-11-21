// ============================================================================
// DATSAN ONLINE - OTP SECURITY & RATE LIMITING SERVICE
// ============================================================================

const OTP_LIMITS = {
  COOLDOWN_MS: 60 * 1000,          // Cooldown 60s giữa 2 lần gửi liên tiếp cho 1 SĐT
  PHONE_WINDOW_MS: 15 * 60 * 1000, // Cửa sổ kiểm tra 15 phút cho 1 SĐT
  PHONE_MAX_REQUESTS: 5,           // Tối đa 5 lần gửi OTP / 15 phút cho 1 SĐT
  IP_WINDOW_MS: 15 * 60 * 1000,    // Cửa sổ kiểm tra 15 phút cho 1 IP
  IP_MAX_REQUESTS: 15,             // Tối đa 15 lần gửi OTP / 15 phút cho 1 IP
  EXPIRATION_MS: 5 * 60 * 1000,    // Thời hạn hiệu lực của OTP: 5 phút (300s)
  MAX_VERIFY_FAILS: 5,             // Tối đa 5 lần xác minh sai liên tiếp
  LOCKOUT_MS: 15 * 60 * 1000,      // Thời gian khóa sau 5 lần sai: 15 phút
};

const otpRequestsByPhone = new Map(); // phone -> { lastSentAt, sendCount, windowStart }
const otpRequestsByIp = new Map();    // ip -> { count, windowStart }
const otpVerifyState = new Map();      // phone -> { failedAttempts, lockedUntil }
const otpIssuedState = new Map();      // phone -> { issuedAt, expiresAt }

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Kiểm tra Rate Limiting trước khi gửi mã OTP
 */
function checkOtpRateLimit(req, phone) {
  const now = Date.now();
  const ip = getClientIp(req);

  // 1. Kiểm tra tài khoản có đang bị khóa xác minh do nhập sai quá 5 lần không
  const verifyData = otpVerifyState.get(phone);
  if (verifyData?.lockedUntil && now < verifyData.lockedUntil) {
    const remainingSec = Math.ceil((verifyData.lockedUntil - now) / 1000);
    return {
      allowed: false,
      status: 429,
      error: `Tài khoản tạm thời bị khóa do nhập sai mã OTP quá 5 lần. Vui lòng thử lại sau ${remainingSec} giây.`,
      lockRemaining: remainingSec,
    };
  }

  // 2. IP Rate Limit: Tối đa 15 yêu cầu / 15 phút
  let ipRecord = otpRequestsByIp.get(ip);
  if (!ipRecord || (now - ipRecord.windowStart > OTP_LIMITS.IP_WINDOW_MS)) {
    ipRecord = { count: 0, windowStart: now };
    otpRequestsByIp.set(ip, ipRecord);
  }
  if (ipRecord.count >= OTP_LIMITS.IP_MAX_REQUESTS) {
    return {
      allowed: false,
      status: 429,
      error: 'Quá nhiều yêu cầu gửi mã OTP từ địa chỉ IP này. Vui lòng thử lại sau 15 phút.',
    };
  }

  // 3. Phone Cooldown & Phone Max Requests
  let phoneRecord = otpRequestsByPhone.get(phone);
  if (phoneRecord) {
    // 3a. Cooldown 60 giây
    const timeSinceLast = now - phoneRecord.lastSentAt;
    if (timeSinceLast < OTP_LIMITS.COOLDOWN_MS) {
      const waitSec = Math.ceil((OTP_LIMITS.COOLDOWN_MS - timeSinceLast) / 1000);
      return {
        allowed: false,
        status: 429,
        error: `Vui lòng chờ ${waitSec} giây trước khi yêu cầu gửi lại mã OTP mới.`,
        retryAfter: waitSec,
      };
    }

    // 3b. Cửa sổ 15 phút
    if (now - phoneRecord.windowStart > OTP_LIMITS.PHONE_WINDOW_MS) {
      phoneRecord.sendCount = 0;
      phoneRecord.windowStart = now;
    }

    // 3c. Giới hạn tối đa 5 lần
    if (phoneRecord.sendCount >= OTP_LIMITS.PHONE_MAX_REQUESTS) {
      return {
        allowed: false,
        status: 429,
        error: 'Số điện thoại này đã gửi quá 5 lần OTP trong 15 phút. Vui lòng thử lại sau.',
      };
    }
  } else {
    phoneRecord = { lastSentAt: 0, sendCount: 0, windowStart: now };
    otpRequestsByPhone.set(phone, phoneRecord);
  }

  // Tăng đếm
  ipRecord.count++;
  phoneRecord.lastSentAt = now;
  phoneRecord.sendCount++;

  // Ghi nhận phát hành OTP có thời hạn 5 phút
  otpIssuedState.set(phone, {
    issuedAt: now,
    expiresAt: now + OTP_LIMITS.EXPIRATION_MS,
  });

  return {
    allowed: true,
    expiresIn: Math.floor(OTP_LIMITS.EXPIRATION_MS / 1000),
    cooldown: Math.floor(OTP_LIMITS.COOLDOWN_MS / 1000),
  };
}

/**
 * Kiểm tra trạng thái khóa xác minh
 */
function checkOtpVerifyLock(phone) {
  const now = Date.now();
  const verifyData = otpVerifyState.get(phone);
  if (verifyData?.lockedUntil) {
    if (now < verifyData.lockedUntil) {
      const remainingSec = Math.ceil((verifyData.lockedUntil - now) / 1000);
      return {
        locked: true,
        status: 429,
        error: `Tài khoản tạm thời bị khóa do nhập sai mã OTP quá 5 lần. Vui lòng thử lại sau ${remainingSec} giây.`,
        lockRemaining: remainingSec,
      };
    } else {
      otpVerifyState.delete(phone);
    }
  }
  return { locked: false };
}

/**
 * Kiểm tra thời hạn hiệu lực của OTP (5 phút)
 */
function checkOtpExpiration(phone) {
  const now = Date.now();
  const issuedData = otpIssuedState.get(phone);
  if (issuedData && now > issuedData.expiresAt) {
    return {
      expired: true,
      status: 400,
      error: 'Mã OTP đã hết hạn (chỉ có hiệu lực trong 5 phút). Vui lòng yêu cầu mã mới.',
    };
  }
  return { expired: false };
}

/**
 * Xử lý khi xác minh THÀNH CÔNG
 */
function handleVerifySuccess(phone) {
  otpVerifyState.delete(phone);
  otpIssuedState.delete(phone);
}

/**
 * Xử lý khi xác minh THẤT BẠI
 */
function handleVerifyFailure(phone, defaultMsg) {
  let verifyData = otpVerifyState.get(phone);
  if (!verifyData) {
    verifyData = { failedAttempts: 0, lockedUntil: null };
    otpVerifyState.set(phone, verifyData);
  }
  verifyData.failedAttempts++;

  if (verifyData.failedAttempts >= OTP_LIMITS.MAX_VERIFY_FAILS) {
    verifyData.lockedUntil = Date.now() + OTP_LIMITS.LOCKOUT_MS;
    return {
      status: 429,
      error: 'Bạn đã nhập sai mã OTP 5 lần liên tiếp. Tài khoản bị tạm khóa xác minh trong 15 phút.',
      lockRemaining: Math.floor(OTP_LIMITS.LOCKOUT_MS / 1000),
    };
  }

  const remainingTries = OTP_LIMITS.MAX_VERIFY_FAILS - verifyData.failedAttempts;
  return {
    status: 401,
    error: `Mã xác thực không chính xác. Bạn còn ${remainingTries} lần thử.`,
    remainingAttempts: remainingTries,
  };
}

/**
 * Reset giới hạn cho testing
 */
function resetOtpLimits(phone, ip) {
  if (phone) {
    otpRequestsByPhone.delete(phone);
    otpVerifyState.delete(phone);
    otpIssuedState.delete(phone);
  }
  if (ip) {
    otpRequestsByIp.delete(ip);
  }
}

// Tự động dọn dẹp bộ nhớ mỗi 10 phút
setInterval(() => {
  const now = Date.now();
  for (const [phone, data] of otpRequestsByPhone.entries()) {
    if (now - data.windowStart > OTP_LIMITS.PHONE_WINDOW_MS) {
      otpRequestsByPhone.delete(phone);
    }
  }
  for (const [ip, data] of otpRequestsByIp.entries()) {
    if (now - data.windowStart > OTP_LIMITS.IP_WINDOW_MS) {
      otpRequestsByIp.delete(ip);
    }
  }
  for (const [phone, data] of otpVerifyState.entries()) {
    if (data.lockedUntil && now > data.lockedUntil && data.failedAttempts >= OTP_LIMITS.MAX_VERIFY_FAILS) {
      otpVerifyState.delete(phone);
    }
  }
  for (const [phone, data] of otpIssuedState.entries()) {
    if (now > data.expiresAt) {
      otpIssuedState.delete(phone);
    }
  }
}, 10 * 60 * 1000).unref();

module.exports = {
  OTP_LIMITS,
  checkOtpRateLimit,
  checkOtpVerifyLock,
  checkOtpExpiration,
  handleVerifySuccess,
  handleVerifyFailure,
  resetOtpLimits,
};
