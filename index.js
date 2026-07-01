#!/usr/bin/env node
/* MisAnthropic v2.0.0 — WSL Edition
 *
 * 检测客户端隐写检查可能依赖的地理指纹信号。
 * 基于已公开的逆向分析资料，纯文件系统扫描——不联网，不上传。
 *
 * Usage:
 *   node index.js              pretty output
 *   node index.js --json        machine-readable
 *   node index.js --summary     verdict only
 *   node index.js --no-color    plain text
 *   node index.js --fix         fix guide
 *   node index.js --debug       显示未命中的检查项（clean 记录），用于排查"为什么没检测到"
 *   node index.js --demo-clean  无条件显示"干净用户"界面（不管实际检测到多少信号）
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');

// ─── helpers ────────────────────────────────────────────────────────────────

const ARGS    = process.argv.slice(2);
const JSON_MODE = ARGS.includes('--json');
const NO_COLOR  = ARGS.includes('--no-color') || !process.stdout.isTTY;
const SUMMARY   = ARGS.includes('--summary');
const FIX_MODE  = ARGS.includes('--fix');
const DEBUG     = ARGS.includes('--debug');
const DEMO_CLEAN = ARGS.includes('--demo-clean');

const R = NO_COLOR ? '' : '\x1b[31m';
const G = NO_COLOR ? '' : '\x1b[32m';
const Y = NO_COLOR ? '' : '\x1b[33m';
const C = NO_COLOR ? '' : '\x1b[36m';
const B = NO_COLOR ? '' : '\x1b[1m';
const D = NO_COLOR ? '' : '\x1b[2m';
const X = NO_COLOR ? '' : '\x1b[0m';

const SILENT = Symbol('silent');
const DEDUP  = new Set(); // global dedup key set

function sh(cmd, opts = {}) {
  try { return execSync(cmd, { encoding: 'utf-8', timeout: 3000, ...opts }).trim(); }
  catch { return SILENT; }
}

function exists(p) {
  try { fs.accessSync(p, fs.constants.R_OK); return true; }
  catch { return false; }
}

function readFile(p) {
  try { return fs.readFileSync(p, 'utf-8'); }
  catch { return SILENT; }
}

function readDir(p) {
  try { return fs.readdirSync(p); }
  catch { return SILENT; }
}

function statSize(p) {
  try { return fs.statSync(p).size; }
  catch { return 0; }
}

/** Scan a directory for entries matching any of the given strings or regexps. */
function globMatch(base, ...patterns) {
  if (!exists(base)) return [];
  const entries = readDir(base);
  if (entries === SILENT) return [];
  const hits = [];
  for (const e of entries) {
    for (const p of patterns) {
      if (typeof p === 'string') {
        if (e.toLowerCase().includes(p.toLowerCase())) { hits.push(e); break; }
      } else if (p instanceof RegExp) {
        if (p.test(e)) { hits.push(e); break; }
      }
    }
  }
  return hits;
}

/** Record a finding with automatic dedup. Returns null if already reported. */
function finding(evidence, severity, solution) {
  const key = `${severity}:${evidence.slice(0, 80)}`;
  if (DEDUP.has(key)) return null;
  DEDUP.add(key);
  return { found: true, evidence, severity, solution };
}

function clean(evidence) {
  DEDUP.add(`__clean__:${evidence}`);
  return { found: false, evidence, severity: 'P0', solution: '' };
}

// ─── detector registry ──────────────────────────────────────────────────────

/** @type {Array<{id:string, label:string, run: ()=>CheckResult[]}>} */
const detectors = [];
function register(id, label, run) { detectors.push({ id, label, run }); }

// ─── platform detection ─────────────────────────────────────────────────────

const IS_WSL = (() => {
  const release = readFile('/proc/sys/kernel/osrelease') || '';
  return /microsoft|WSL/i.test(release);
})();

const MNT_C = (() => {
  if (!IS_WSL) return false;
  return exists('/mnt/c/Windows/System32/drivers/etc/hosts');
})();

let _windowsUsersCache;
function windowsUsers() {
  if (!MNT_C) return [];
  if (_windowsUsersCache) return _windowsUsersCache;
  const users = readDir('/mnt/c/Users');
  if (users === SILENT) return (_windowsUsersCache = []);
  _windowsUsersCache = users.filter(u => {
    if (u.startsWith('.') || u === 'desktop.ini') return false;
    if (['Public', 'All Users', 'Default', 'Default User', 'DefaultAppPool', 'defaultuser0'].includes(u)) return false;
    // Only include dirs that have AppData (real user profiles)
    return exists(`/mnt/c/Users/${u}/AppData`);
  });
  return _windowsUsersCache;
}

// ─── D0: timezone ───────────────────────────────────────────────────────────

register('timezone', '时区与系统区域', () => {
  const results = [];

  // Claude Code's Crt() only checks Asia/Shanghai and Asia/Urumqi
  const mainlandTZ = ['Asia/Shanghai', 'Asia/Urumqi', 'Asia/Chongqing',
                       'Asia/Harbin', 'Asia/Kashgar'];
  const tzFile = readFile('/etc/timezone');

  if (tzFile !== SILENT) {
    const tz = tzFile.trim();
    if (mainlandTZ.includes(tz)) {
      const f = finding(`/etc/timezone = "${tz}" → 中国大陆时区`, 'P1',
        'sudo timedatectl set-timezone Asia/Singapore');
      if (f) results.push(f);
    } else {
      results.push(clean(`时区: ${tz} (不在中国大陆时区名单)`));
    }
  } else {
    results.push(clean('无法读取 /etc/timezone'));
  }

  // TZ env var
  const tzEnv = process.env.TZ;
  if (tzEnv && mainlandTZ.includes(tzEnv.trim())) {
    const f = finding(`TZ=${tzEnv}`, 'P1', 'unset TZ');
    if (f) results.push(f);
  }

  return results;
});

// ─── D1: locale ─────────────────────────────────────────────────────────────

register('locale', '语言环境 (Locale)', () => {
  const results = [];
  const lang = process.env.LANG || '';
  const allLocales = sh('locale 2>/dev/null') || '';

  // zh_CN / zh-CN 是关键信号。zh_TW/SG 已删除（非大陆，意义弱）；
  // zh_HK/zh-HK 保留但仅 P3（香港区域，弱信号）。
  const cnRe = /zh_CN|zh-CN/i;
  const hkRe = /zh_HK|zh-HK/i;

  if (cnRe.test(lang) || cnRe.test(allLocales)) {
    const f = finding(`LANG/locale 含 zh_CN (简体中文): ${lang}`,
      'P1', 'export LANG=en_US.UTF-8; sudo update-locale LANG=en_US.UTF-8');
    if (f) results.push(f);
  } else if (hkRe.test(lang) || hkRe.test(allLocales)) {
    const f = finding(`LANG/locale 含 zh_HK (香港区域): ${lang}`,
      'P3', '如需完全消除中文痕迹: export LANG=en_US.UTF-8');
    if (f) results.push(f);
  } else {
    results.push(clean(`LANG="${lang || '未设置'}" — 非中文区域`));
  }

  return results;
});

// ─── D2: /mnt/c/ filesystem ─────────────────────────────────────────────────

register('fs-mnt', 'Windows 挂载点指纹 (/mnt/c/)', () => {
  const results = [];

  if (!MNT_C) {
    results.push(clean('/mnt/c/ 未挂载或不可读 — P0 指纹源已关闭'));
    return results;
  }

  const users = windowsUsers();

  /** 按命中数量分级：≥5=P0，≥3=P1，≥1=P2。返回 {sev, hits} */
  function tierByCount(hits) {
    const n = hits.length;
    const sev = n >= 5 ? 'P0' : n >= 3 ? 'P1' : 'P2';
    return { sev, n };
  }

  // ── 2.1 Installed software（按数量分级） ────────────────────────────────
  // Program Files 下安装目录名关键词 —— 大胆枚举国产/中国厂商软件
  const chineseApps = [
    // 腾讯系
    'Tencent', 'WeChat', 'Weixin', 'QQ', 'QQEX', 'qqgameshare', 'QQPlayer',
    'TIM', 'QQ音乐', '腾讯会议', '腾讯QQ', '腾讯视频', 'QQGame', 'Foxmail',
    'QQ电脑管家', 'QQMgr', 'tencentdocs', '腾讯文档',
    // 阿里系
    'AliWangWang', 'AliIM', 'DingTalk', '钉钉', 'Alibaba', 'AlibabaProtect',
    'Aliyun', 'AliYunPangu', 'aegis', '千牛', '淘宝', '支付宝',
    // 百度系
    'Baidu', 'baidu', 'BaiduYunGuanjia', 'BaiduYunKernel', 'baidunetdisk',
    '百度网盘', '百度云', 'BaiduHi', 'BaiduPlayer', 'Hao123', '百度卫士',
    'BaiduSd', 'BaiduAn', '百度输入法',
    // 网易/游戏
    'Netease', '网易', 'NetEase', 'YY', '网易雷神', 'UU加速器', 'UUOnline',
    'NeteaseMusic', '网易云音乐', '梦幻', '大话', '阴阳师', 'yys',
    // 影音娱乐
    'IQIYI', '爱奇艺', 'Youku', '优酷', 'Kugou', '酷狗', 'KuGou', '酷我',
    'kuwo', 'Ximalaya', '喜马拉雅', 'bilibili', '哔哩哔哩', 'BiliBili',
    '芒果TV', 'mgtv', '斗鱼', '虎牙', 'huya', 'douyu', '快手', 'Kuaishou',
    'Kwai', '抖音', 'douyin', 'TikTok', '西瓜视频',
    // 办公/输入法/工具
    'Sogou', '搜狗', 'SogouInput', 'SogouExplorer', '搜狗浏览器',
    'WPS', 'WPSOffice', '金山', 'Kingsoft', 'Xunlei', '迅雷', 'Thunder',
    '迅雷下载', '百度翻译', '有道', 'Youdao', 'fanyi', '360', '360safe',
    '360安全卫士', '360Chrome', '360压缩', '2345', '安全卫士', '猎豹',
    'Cheetah', 'liebao',
    // 安全/系统
    '360Tray', '360Safe', '360sd', 'ZhuDongFangYu', '腾讯电脑管家',
    '管家', '2345Explorer', 'hao123',
    // 远程/终端/开发
    'Xshell', 'Xmanager', 'Xftp', 'Sunlogin', '向日葵', 'ToDesk', 'todesk',
    'TeamDog', 'rustdesk', 'MobaXterm', 'finalshell', 'FinalShell',
    'Navicat', 'Postman-cn', 'Apifox', 'apifox', 'eolink',
    // 网盘/云盘/下载
    '天翼云盘', 'ecloud', 'Ecloud', '115', '115chrome', '阿里云盘',
    'alipan', '迅雷云盘', '夸克网盘', 'quark',
    // 浏览器
    '360se', '360Chrome', 'Maxthon', '遨游', '傲游', '搜狗高速浏览器',
    'QQBrowser', 'QQ浏览器', 'UCBrowser', '夸克',
    // 其他厂商
    'Kingsoft', '科大讯飞', 'iFlytek', 'iflytime', '讯飞', 'Xunfei',
    '小米', 'Xiaomi', 'MiPc', '华为', 'Huawei', 'HiSuite', '华为手机助手',
    'OPPO', 'vivo', 'Meizu', '一加', 'OnePlus', 'realme',
    'Lenovo', '联想', '联想电脑管家',
    // 教育/会议
    '腾讯会议', 'WeMeet', 'wemeetapp', '飞书', 'Feishu', 'Lark',
    '企业微信', 'WXWork', '钉钉', 'Zoom-cn',
    // 老牌国产
    'Xunlei', 'emule', 'VeryCD', '电驴', 'QQGame', 'Baofeng', '暴风',
    'BaofengPlayer', '暴风影音', 'Kankan', '迅雷看看', 'QQLive',
    'QQLive', '腾讯视频', 'PPTV', 'PPLive', '风行', 'Funshion',
  ];
  let appHits = [];
  for (const d of ['/mnt/c/Program Files', '/mnt/c/Program Files (x86)']) {
    for (const h of globMatch(d, ...chineseApps)) appHits.push(`${d.split('/').pop()}/${h}`);
  }
  if (appHits.length > 0) {
    const { sev, n } = tierByCount(appHits);
    const f = finding(`已安装 ${n} 个中国软件: ${appHits.slice(0, 5).join(', ')}${appHits.length > 5 ? ' …' : ''}`, sev,
      `卸载这些软件 或 在 wsl.conf 设置 [automount] enabled=false`);
    if (f) results.push(f);
  }

  // ── 2.2 Desktop shortcuts（按数量分级） ─────────────────────────────────
  // Public Desktop 下快捷方式名关键词（.lnk 通常不显示后缀，但 globMatch 按包含匹配）
  const pubDesktop = '/mnt/c/Users/Public/Desktop';
  const deskPatterns = [
    /[一-鿿]/,                       // 任何含中文的快捷方式名
    // 腾讯系
    'QQ', 'WeChat', 'Weixin', '微信', 'TIM', '腾讯会议', 'WeMeet', '腾讯视频',
    'QQLive', 'QQ音乐', 'QQBrowser', 'QQ浏览器', 'Foxmail', 'QQ电脑管家',
    // 阿里/钉钉/飞书
    '钉钉', 'DingTalk', '千牛', '阿里旺旺', 'AliWangWang', '飞书', 'Feishu',
    'Lark', '企业微信', 'WXWork', '支付宝',
    // 百度
    '百度网盘', '百度云盘', '百度', 'BaiduNetdisk', '百度输入法', '百度翻译',
    '百度卫士', 'Hao123',
    // 网盘/下载
    '天翼云盘', 'ecloud', '迅雷', 'Xunlei', 'Thunder', '115', '阿里云盘',
    'alipan', '夸克网盘', 'UC网盘',
    // 影音
    '爱奇艺', 'IQIYI', '优酷', 'Youku', '酷狗', 'Kugou', '酷我', 'kuwo',
    '网易云音乐', 'NeteaseMusic', 'QQ音乐', '喜马拉雅', 'Ximalaya',
    'bilibili', '哔哩哔哩', '芒果TV', '斗鱼', '虎牙', '抖音', 'douyin',
    '快手', 'Kuaishou', '西瓜视频',
    // 输入法/办公
    '搜狗输入法', 'SogouInput', '搜狗', 'WPS', 'WPSOffice', '金山', '有道',
    'Youdao', '百度翻译',
    // 浏览器/安全
    '360安全卫士', '360浏览器', '360Chrome', '360se', '2345', '腾讯电脑管家',
    '猎豹', 'Maxthon', '傲游', '搜狗高速浏览器',
    // 远程/终端
    '向日葵', 'Sunlogin', 'ToDesk', 'todesk', 'Xshell', 'FinalShell',
    // 加速器/游戏
    'UU加速器', 'UUOnline', '网易雷神', '腾讯游戏', 'WeGame',
    // 网盘备份
    'OneDrive-腾讯', '微云', 'WeiYun',
  ];
  const deskHits = globMatch(pubDesktop, ...deskPatterns);
  if (deskHits.length > 0) {
    const { sev, n } = tierByCount(deskHits);
    const f = finding(`Public Desktop ${n} 个中文/国产软件快捷方式: ${deskHits.slice(0, 5).join(', ')}`, sev,
      `删除 /mnt/c/Users/Public/Desktop/ 下的相关快捷方式`);
    if (f) results.push(f);
  }

  // ── 2.3 AppData（按数量分级） ───────────────────────────────────────────
  // AppData\Roaming 下国产软件残留目录名关键词
  const appDataApps = [
    // 腾讯系
    'Tencent', 'Tencent Files', 'TencentDocs', '腾讯文档', 'QQ', 'QQEX',
    'WeChat', 'Weixin', 'xwechat', 'qqgameshare', 'QQPlayer', 'TIM',
    'WeMeet', '腾讯会议', 'QQLive', '腾讯视频', 'QQ音乐', 'QQBrowser',
    'QQ浏览器', 'Foxmail', 'QQPet', 'WeGame', '腾讯电脑管家', 'QQMgr',
    'TencentMeeting', '微云', 'WeiYun', 'QQGame',
    // 阿里系
    'AliWangWang', 'AliIM', '千牛', 'DingTalk', '钉钉', '钉钉PC',
    'Alibaba', 'Aliyun', 'aegis', 'AlibabaProtect', 'alipan', '阿里云盘',
    '淘宝', '支付宝',
    // 百度系
    'BaiduYunGuanjia', 'BaiduYunKernel', 'baidu', 'baidunetdisk',
    '百度网盘', '百度云盘', 'BaiduHi', 'BaiduPlayer', 'BaiduSd', 'BaiduAn',
    '百度输入法', '百度卫士', 'BaiduTranslate', '百度翻译', 'Hao123',
    // 网易
    'Netease', 'NetEase', '网易', 'NeteaseMusic', '网易云音乐', 'UU加速器',
    'UUOnline', '网易雷神', '有道', 'Youdao', '有道云笔记', 'youdaonote',
    // 影音娱乐
    'IQIYI', '爱奇艺', 'Youku', '优酷', 'Kugou', '酷狗', 'KuGou', '酷我',
    'kuwo', 'Ximalaya', '喜马拉雅', 'bilibili', '哔哩哔哩', 'BiliBili',
    '芒果TV', 'mgtv', '斗鱼', 'douyu', '虎牙', 'huya', '快手', 'Kuaishou',
    'Kwai', '抖音', 'douyin', 'TikTok', '西瓜视频',
    // 输入法/办公
    'Sogou', '搜狗', 'SogouInput', 'SogouExplorer', '搜狗输入法',
    'SogouCloud', 'WPS', 'WPSOffice', 'Kingsoft', '金山', '金山文档',
    'SogouBrowser', '百度输入法',
    // 浏览器/安全
    '360', '360se', '360Chrome', '360安全卫士', '360Safe', '360Tray',
    '2345', '2345Explorer', '猎豹', 'Cheetah', 'liebao', 'Maxthon', '傲游',
    '搜狗高速浏览器', 'UCBrowser', 'UC',
    // 远程/终端/开发
    'Xshell', 'Xmanager', 'Xftp', 'Sunlogin', '向日葵', 'ToDesk', 'todesk',
    'rustdesk', 'FinalShell', 'finalshell', 'MobaXterm', 'Apifox', 'apifox',
    'eolink', 'Navicat',
    // 网盘/云盘
    '天翼云盘', 'ecloud', 'Ecloud', '115', '115chrome', '夸克网盘', 'quark',
    '迅雷', 'Xunlei', 'Thunder', '迅雷云盘',
    // 飞书/会议
    'Feishu', '飞书', 'Lark', 'LarkShell', '企业微信', 'WXWork',
    'Zoom', '腾讯会议', 'WeMeet',
    // 讯飞/语音
    'iFlytek', '讯飞', 'iflytime', '科大讯飞', 'Xunfei', 'iflyrec',
    '讯飞听见', '讯飞输入法',
    // 手机助手
    'HiSuite', '华为手机助手', 'MiPhoneAssistant', '小米助手', 'OPPO',
    'vivo助手', '联想手机助手', 'Lenovo',
    // 老牌影音
    'Baofeng', '暴风', 'BaofengPlayer', 'Kankan', '迅雷看看', 'PPTV',
    'PPLive', '风行', 'Funshion', 'VeryCD', '电驴',
  ];
  let appDataHits = [];
  for (const u of users) {
    const roaming = `/mnt/c/Users/${u}/AppData/Roaming`;
    for (const h of globMatch(roaming, ...appDataApps)) {
      appDataHits.push(`AppData\\Roaming\\${h} (用户: ${u})`);
    }
  }
  if (appDataHits.length > 0) {
    const { sev, n } = tierByCount(appDataHits);
    const f = finding(`AppData/Roaming ${n} 个国产软件目录: ${appDataHits.slice(0, 5).join(', ')}`, sev,
      `卸载相关软件并清理 AppData`);
    if (f) results.push(f);
  }

  // ── 2.4 Chinese usernames（P2，合并显示） ───────────────────────────────
  const cnUsernames = users
    .filter(u => /[一-鿿㐀-䶿]/.test(u))
    .map(u => {
      // 繁体字有独立码位；若无繁体字则标记"疑似简中"
      const note = /[變魚為國業學習個們東車馬風見門長時實發開關對]/.test(u) ? '' : ' (疑似简中)';
      return `"${u}"${note}`;
    });
  if (cnUsernames.length > 0) {
    const f = finding(`${cnUsernames.length} 个 Windows 用户名含中文: ${cnUsernames.join(', ')}`, 'P2',
      '重命名 Windows 用户账户，或新建一个 ASCII 用户名账户');
    if (f) results.push(f);
  }

  // ── 2.5 WiFi SSIDs（按数量分级 + 扩充关键词） ──────────────────────────
  // 中国运营商前缀与运营商相关 SSID 关键词
  const wifiCNKeywords = [
    /^CU_/i,            // 中国联通
    /^CMCC-/i, /^CMCC_/i, // 中国移动
    /^ChinaNet/i,       // 中国电信
    /^ChinaUnicom/i,
  ];
  const wifiBase = '/mnt/c/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces';
  let wifiHits = [];
  const seenSSID = new Set(); // 同一 SSID 可能在多个配置文件/接口下重复，按 SSID 去重
  if (exists(wifiBase)) {
    const ifaces = readDir(wifiBase);
    if (ifaces !== SILENT) {
      for (const iface of ifaces) {
        const pdir = path.join(wifiBase, iface);
        const profiles = readDir(pdir);
        if (profiles === SILENT) continue;
        for (const pf of profiles) {
          const content = readFile(path.join(pdir, pf));
          if (content === SILENT) continue;
          const ssidM = content.match(/<name>(.+?)<\/name>/g);
          if (!ssidM) continue;
          for (const m of ssidM) {
            const ssid = m.replace(/<\/?name>/g, '');
            if (seenSSID.has(ssid)) continue;
            const isCNKw = wifiCNKeywords.some(re => re.test(ssid));
            const isCJK = /[一-鿿]/.test(ssid);
            if (isCNKw || isCJK) {
              seenSSID.add(ssid);
              const tag = isCNKw ? '运营商/中国关键词前缀' : '含中文';
              wifiHits.push(`"${ssid}" (${tag})`);
            }
          }
        }
      }
    }
  }
  if (wifiHits.length > 0) {
    const { sev, n } = tierByCount(wifiHits);
    const f = finding(`WiFi SSID ${n} 个中国相关: ${wifiHits.slice(0, 5).join(', ')}`, sev,
      '删除 WiFi 配置文件');
    if (f) results.push(f);
  }

  // ── 2.6 PowerShell history ──────────────────────────────────────────────
  // 把 .edu.cn / 典型中国域名 / 其他裸 .cn 合并成一条 finding，避免对同一份历史文件输出多行
  for (const u of users) {
    const psPath = `/mnt/c/Users/${u}/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`;
    const hist = readFile(psPath);
    if (hist === SILENT) continue;

    const lines = hist.split('\n');
    const parts = [];
    let sev = 'P2';

    // .edu.cn — 强信号，命中即升 P1
    const eduLines = lines.filter(l => /\.edu\.cn\b/.test(l));
    if (eduLines.length > 0) {
      sev = 'P1';
      const ex = eduLines[0].match(/[\w.-]*\.edu\.cn\b/i)?.[0] || '.edu.cn';
      parts.push(`.edu.cn 域名 (如 ${ex})`);
    }

    // 典型中国域名/服务
    const hits = CN_DOMAIN_HITS(hist);
    if (hits.length > 0) parts.push(hits.slice(0, 4).join(', '));

    // 其他裸 .cn 域名（非 edu、未被典型名单命中）
    const namedHit = l => CN_DOMAIN_PATTERNS.some(p => p.re.test(l));
    const bareCn = lines.filter(l => /\.cn\b/.test(l) && !/\.edu\.cn\b/.test(l) && !namedHit(l));
    if (bareCn.length > 0) {
      const ex = bareCn[0].match(/[\w.-]*\.cn\b/i)?.[0] || '.cn';
      parts.push(`其他 .cn 域名 ${bareCn.length} 处 (如 ${ex})`);
    }

    if (parts.length > 0) {
      const f = finding(`PowerShell 历史含中国相关域名 (${u}): ${parts.join(' | ')}`, sev, `删除 ${psPath}`);
      if (f) results.push(f);
    }
  }

  // ── 2.7 Registry: InstallLanguage ──────────────────────────────────────
  // Try to read via reg.exe if /mnt/c is accessible (WSL interop may work even without mount)
  const regLang = sh('reg.exe query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language" /v InstallLanguage 2>/dev/null');
  if (regLang !== SILENT && /0804/.test(regLang)) {
    const f = finding('Windows InstallLanguage = 0804 (zh-CN 简体中文)', 'P1',
      '无法安全修改，Windows 系统语言在安装时确定');
    if (f) results.push(f);
  }

  return results;
});

// ─── D3: Shell history & dotfiles ───────────────────────────────────────────

// 典型中国域名/服务 —— 用户日常 ping/curl/git clone 等会留下的痕迹。
// 按类别分组，命中后返回可读标签列表。
const CN_DOMAIN_PATTERNS = [
  // 搜索/门户
  { re: /\bbaidu\.com\b/i,         tag: 'baidu.com (百度)', dom: 'baidu' },
  { re: /\bbdstatic\.com\b/i,      tag: 'bdstatic.com (百度静态资源)', dom: 'bdstatic' },
  { re: /\bsogou\.com\b/i,         tag: 'sogou.com (搜狗)', dom: 'sogou' },
  { re: /\bso\.com\b/i,            tag: 'so.com (360搜索)', dom: 'so' },
  { re: /\bhao123\.com\b/i,        tag: 'hao123.com (百度导航)', dom: 'hao123' },
  { re: /\b2345\.com\b/i,          tag: '2345.com (导航站)', dom: '2345' },
  // 电商
  { re: /\btaobao\.com\b/i,        tag: 'taobao.com (淘宝)', dom: 'taobao.com' },
  { re: /\btmall\.com\b/i,         tag: 'tmall.com (天猫)', dom: 'tmall' },
  { re: /\bJD\.com\b/i,            tag: 'JD.com (京东)', dom: 'jd' },
  { re: /\btaobao\.org\b/i,        tag: 'taobao.org', dom: 'taobao.org' },
  // 社交/社区
  { re: /\bweibo\.com\b/i,         tag: 'weibo.com (微博)', dom: 'weibo' },
  { re: /\bzhihu\.com\b/i,         tag: 'zhihu.com (知乎)', dom: 'zhihu' },
  { re: /\bdouban\.com\b/i,        tag: 'douban.com (豆瓣)', dom: 'douban' },
  { re: /\bbilibili\.com\b/i,      tag: 'bilibili.com (B站)', dom: 'bilibili' },
  { re: /\bctrip\.com\b/i,         tag: 'ctrip.com (携程)', dom: 'ctrip' },
  // 云/CDN
  { re: /\baliyuncs\.com\b/i,      tag: 'aliyuncs.com (阿里云)', dom: 'aliyuncs' },
  { re: /\bmyhuaweicloud\.com\b/i, tag: 'myhuaweicloud.com (华为云)', dom: 'myhuaweicloud' },
  { re: /\btencentcloudapi\.com\b/i, tag: 'tencentcloudapi.com (腾讯云)', dom: 'tencentcloudapi' },
  { re: /\bdnspod\.cn\b/i,         tag: 'dnspod.cn (DNSPod)', dom: 'dnspod' },
  // 工具/SDK —— dom 与 mirrorPatterns 对齐，bash 端去重用
  { re: /\bnpmmirror\.com\b/i,     tag: 'npmmirror.com (淘宝npm镜像)', dom: 'npmmirror' },
  { re: /\bgitee\.com\b/i,         tag: 'gitee.com (码云)', dom: 'gitee' },
  { re: /\bcoding\.net\b/i,        tag: 'coding.net (CODING)', dom: 'coding' },
  { re: /\biconfont\.cn\b/i,       tag: 'iconfont.cn (阿里图标库)', dom: 'iconfont' },
  { re: /\bcnpmjs\.org\b/i,        tag: 'cnpmjs.org (国内 npm)', dom: 'cnpmjs' },
  // 常见网盘/下载
  { re: /\bpan\.baidu\.com\b/i,    tag: 'pan.baidu.com (百度网盘)', dom: 'pan.baidu' },
];
/** 在文本中查找命中的中国域名，返回标签数组。excludeDoms 中的域名跳过（用于去重）。 */
function CN_DOMAIN_HITS(text, excludeDoms = new Set()) {
  const out = [];
  for (const { re, tag, dom } of CN_DOMAIN_PATTERNS) {
    if (excludeDoms.has(dom)) continue;
    if (re.test(text)) out.push(tag);
  }
  return out;
}

register('dotfiles', 'Shell 历史与配置文件', () => {
  const results = [];
  const home = os.homedir();
  const historyFiles = ['.bash_history', '.zsh_history', '.fish_history'];

  const mirrorPatterns = [
    { re: /npmmirror\.com/,       tag: 'npmmirror.com (淘宝 npm 镜像)', sev: 'P0', dom: 'npmmirror' },
    { re: /registry\.npm\.taobao\.org/, tag: 'npm.taobao.org (淘宝旧镜像)', sev: 'P0', dom: 'npm.taobao' },
    { re: /mirrors\.aliyun\.com/, tag: 'mirrors.aliyun.com (阿里云)', sev: 'P1', dom: 'aliyun-mirror' },
    { re: /mirrors\.tuna\.tsinghua/, tag: 'tuna.tsinghua.edu.cn (清华)', sev: 'P2', dom: 'tuna-mirror' },
    { re: /mirrors\.ustc\.edu\.cn/, tag: 'ustc.edu.cn (中科大)', sev: 'P2', dom: 'ustc-mirror' },
    { re: /gitee\.com/,           tag: 'gitee.com (码云)', sev: 'P1', dom: 'gitee' },
    { re: /goproxy\.cn/,          tag: 'goproxy.cn', sev: 'P2', dom: 'goproxy' },
    { re: /gems\.ruby-china\.com/, tag: 'ruby-china.com (RubyGems)', sev: 'P2', dom: 'ruby-china' },
    { re: /pypi\.tuna\.tsinghua/, tag: 'PyPI 清华镜像', sev: 'P2', dom: 'pypi-tuna' },
  ];

  for (const hf of historyFiles) {
    const hist = readFile(path.join(home, hf));
    if (hist === SILENT) continue;

    // 已被镜像检查命中的域名 —— 在下面的"典型域名"扫描中跳过，避免同一域名出两行
    const matchedMirrorDoms = new Set();
    for (const { re, tag, sev, dom } of mirrorPatterns) {
      if (re.test(hist)) {
        matchedMirrorDoms.add(dom);
        const matchedLines = hist.split('\n').filter(l => re.test(l)).slice(0, 2);
        const f = finding(`${hf}: ${tag} — ${matchedLines.join(' | ').slice(0, 100)}`,
          sev, `history -c && rm ${path.join(home, hf)}`);
        if (f) results.push(f);
      }
    }

    // 典型中国域名访问痕迹（ping/curl/git clone 等场景）；排除已被镜像检查覆盖的域名
    const hits = CN_DOMAIN_HITS(hist, matchedMirrorDoms);
    if (hits.length > 0) {
      const f = finding(`${hf}: 历史含中国域名/服务: ${hits.slice(0, 4).join(', ')}`, 'P2',
        `history -c && rm ${path.join(home, hf)}`);
      if (f) results.push(f);
    }
  }

  // dotfiles: mirror export lines
  for (const df of ['.bashrc', '.zshrc', '.profile', '.bash_aliases']) {
    const content = readFile(path.join(home, df));
    if (content === SILENT) continue;
    const lines = content.split('\n').filter(l =>
      /mirror|taobao|aliyun|tsinghua|ustc|gitee|npmmirror/i.test(l) &&
      /^\s*(export|alias|source|set\s)/i.test(l)
    );
    for (const line of lines) {
      const f = finding(`${df}: ${line.trim().slice(0, 100)}`, 'P1',
        `编辑 ${path.join(home, df)} 删除该行`);
      if (f) results.push(f);
    }
  }

  if (results.length === 0) {
    results.push(clean('Shell 历史和配置文件未发现中国镜像痕迹'));
  }
  return results;
});

// ─── D4: package manager configs ─────────────────────────────────────────────

register('pkg-managers', '包管理器镜像配置', () => {
  const results = [];
  const home = os.homedir();

  // npm
  (() => {
    const npmrc = readFile(path.join(home, '.npmrc'));
    if (npmrc !== SILENT && /npmmirror|taobao|\.cn/i.test(npmrc)) {
      const f = finding(`~/.npmrc: ${npmrc.trim().slice(0, 100)}`, 'P0', '编辑 ~/.npmrc');
      if (f) results.push(f);
    }
    const reg = sh('npm config get registry 2>/dev/null');
    if (reg !== SILENT && /npmmirror|taobao|\.cn/i.test(reg)) {
      const f = finding(`npm registry = ${reg}`, 'P0', 'npm config set registry https://registry.npmjs.org/');
      if (f) results.push(f);
    }
    // npm cache
    if (exists(path.join(home, '.npm/_cacache'))) {
      const cacheStr = sh(`find ${home}/.npm/_cacache -maxdepth 3 -type d 2>/dev/null | head -100`) || '';
      if (/npmmirror|taobao|cdn\.npmmirror/i.test(cacheStr)) {
        const f = finding('npm 缓存残留 npmmirror/taobao 域名', 'P1', 'npm cache clean --force');
        if (f) results.push(f);
      }
    }
  })();

  // pip
  (() => {
    for (const pc of ['.pip/pip.conf', '.config/pip/pip.conf']) {
      const c = readFile(path.join(home, pc));
      if (c !== SILENT && /tuna\.tsinghua|aliyun.*pypi|pypi\.douban|\.cn/i.test(c)) {
        const f = finding(`~/${pc}: ${c.trim().slice(0, 100)}`, 'P1', `编辑 ~/${pc}`);
        if (f) results.push(f);
      }
    }
    if (/\.cn/i.test(process.env.PIP_INDEX_URL || '')) {
      const f = finding(`PIP_INDEX_URL=${process.env.PIP_INDEX_URL}`, 'P1', 'unset PIP_INDEX_URL');
      if (f) results.push(f);
    }
  })();

  // apt
  (() => {
    const src = readFile('/etc/apt/sources.list');
    if (src !== SILENT && /mirrors\.(aliyun|tuna|ustc|163|huawei|tencent)/i.test(src)) {
      const f = finding('/etc/apt/sources.list 指向中国镜像', 'P1', '恢复为 archive.ubuntu.com');
      if (f) results.push(f);
    }
    const srcD = readDir('/etc/apt/sources.list.d');
    if (srcD !== SILENT) {
      for (const fn of srcD) {
        if (!fn.endsWith('.list')) continue;
        const c = readFile(`/etc/apt/sources.list.d/${fn}`);
        if (c !== SILENT && /mirrors\.(aliyun|tuna|ustc|163|huawei|tencent)/i.test(c)) {
          const f = finding(`/etc/apt/sources.list.d/${fn} 指向中国镜像`, 'P1', '删除该文件');
          if (f) results.push(f);
        }
      }
    }
  })();

  // nvm
  if (/npmmirror|taobao|\.cn/i.test(process.env.NVM_NODEJS_ORG_MIRROR || '')) {
    const f = finding(`NVM_NODEJS_ORG_MIRROR=${process.env.NVM_NODEJS_ORG_MIRROR}`, 'P1', 'unset NVM_NODEJS_ORG_MIRROR');
    if (f) results.push(f);
  }

  // docker
  (() => {
    const dj = readFile('/etc/docker/daemon.json');
    if (dj !== SILENT && /mirror\.aliyuncs|\.cn/i.test(dj)) {
      const f = finding('/etc/docker/daemon.json 含中国 registry mirror', 'P2', '编辑 /etc/docker/daemon.json');
      if (f) results.push(f);
    }
    const dc = readFile(path.join(home, '.docker/config.json'));
    if (dc !== SILENT && /\.cn/i.test(dc)) {
      const f = finding('~/.docker/config.json 含中国 registry', 'P2', '编辑 ~/.docker/config.json');
      if (f) results.push(f);
    }
  })();

  // go
  (() => {
    const gp = process.env.GOPROXY || '';
    if (/goproxy\.cn|\.cn/i.test(gp)) {
      const f = finding(`GOPROXY=${gp}`, 'P2', 'unset GOPROXY; go env -w GOPROXY=https://proxy.golang.org,direct');
      if (f) results.push(f);
    }
    const ge = sh('go env GOPROXY 2>/dev/null');
    if (ge !== SILENT && /goproxy\.cn|\.cn/i.test(ge)) {
      const f = finding(`go env GOPROXY = ${ge}`, 'P2', 'go env -w GOPROXY=https://proxy.golang.org,direct');
      if (f) results.push(f);
    }
  })();

  // rust/cargo
  (() => {
    const cc = readFile(path.join(home, '.cargo/config.toml')) || readFile(path.join(home, '.cargo/config'));
    if (cc !== SILENT && /ustc|tuna|aliyun|\.cn/i.test(cc)) {
      const f = finding('~/.cargo/config.toml 含中国镜像', 'P2', '编辑 ~/.cargo/config.toml');
      if (f) results.push(f);
    }
  })();

  // ruby/gem
  (() => {
    const gr = readFile(path.join(home, '.gemrc'));
    if (gr !== SILENT && /ruby-china|\.cn/i.test(gr)) {
      const f = finding(`~/.gemrc: ${gr.trim()}`, 'P2', '编辑 ~/.gemrc');
      if (f) results.push(f);
    }
    const gs = sh('gem sources -l 2>/dev/null');
    if (gs !== SILENT) {
      const cnSources = gs.split('\n').filter(l => /ruby-china|\.cn/i.test(l));
      if (cnSources.length > 0) {
        const f = finding(`gem sources: ${cnSources.join(', ')}`, 'P2', 'gem sources --remove <url>');
        if (f) results.push(f);
      }
    }
  })();

  // yarn / pnpm
  for (const [file, name] of [['.yarnrc', 'yarn'], ['.yarnrc.yml', 'yarn'], ['.pnpmrc', 'pnpm']]) {
    const c = readFile(path.join(home, file));
    if (c !== SILENT && /npmmirror|taobao|\.cn/i.test(c)) {
      const f = finding(`~/${file}: ${c.trim().slice(0, 100)}`, 'P0', `编辑 ~/${file}`);
      if (f) results.push(f);
    }
  }

  // maven
  const ms = readFile(path.join(home, '.m2/settings.xml'));
  if (ms !== SILENT && /aliyun.*nexus|\.cn/i.test(ms)) {
    const f = finding('~/.m2/settings.xml 含中国 Maven 镜像', 'P2', '编辑 ~/.m2/settings.xml');
    if (f) results.push(f);
  }

  // conda
  const ca = readFile(path.join(home, '.condarc'));
  if (ca !== SILENT && /tuna|aliyun|\.cn/i.test(ca)) {
    const f = finding('~/.condarc 含中国镜像', 'P2', '编辑 ~/.condarc');
    if (f) results.push(f);
  }

  // composer (PHP)
  const composerCfg = sh('composer config -g repos 2>/dev/null');
  if (composerCfg !== SILENT && /aliyun|\.cn/i.test(composerCfg)) {
    const f = finding(`composer: ${composerCfg}`, 'P2', 'composer config -g --unset repos.packagist');
    if (f) results.push(f);
  }

  if (results.length === 0) {
    results.push(clean('所有包管理器使用官方默认源'));
  }
  return results;
});

// ─── D5: network ────────────────────────────────────────────────────────────

register('network', '网络指纹', () => {
  const results = [];

  // MAC OUI — known China-associated prefixes
  const chinaOUIs = [
    { prefix: '40:c2:ba', label: 'COMPAL (仁宝) — 昆山工厂' },
    { prefix: '00:e0:4c', label: 'HUAWEI TECHNOLOGIES' },
    { prefix: '28:6e:d4', label: 'HUAWEI TECHNOLOGIES' },
    { prefix: '98:e7:f4', label: 'Xiaomi Communications' },
    { prefix: '38:de:ad', label: 'Lenovo Mobile' },
    { prefix: '54:ee:75', label: 'Wistron (纬创) — 昆山工厂' },
  ];

  const ifaces = os.networkInterfaces();
  for (const [ifName, addrs] of Object.entries(ifaces)) {
    for (const addr of addrs) {
      if (addr.internal || !addr.mac || addr.mac === '00:00:00:00:00:00') continue;
      const macLower = addr.mac.toLowerCase();
      for (const { prefix, label } of chinaOUIs) {
        if (macLower.startsWith(prefix)) {
          const f = finding(`MAC ${addr.mac} (${ifName}) — OUI: ${label}（仅说明网卡可能在中国制造/厂商为中国公司，地理意义很弱）`, 'P3',
            `sudo ip link set dev ${ifName} address <FAKE_MAC>`);
          if (f) results.push(f);
        }
      }
    }
  }

  // DNS
  const resolv = readFile('/etc/resolv.conf');
  if (resolv !== SILENT) {
    const chinaDns = ['114.114.114.114', '114.114.115.115', '223.5.5.5', '223.6.6.6',
                       '180.76.76.76', '119.29.29.29', '182.254.116.116'];
    for (const dns of chinaDns) {
      if (resolv.includes(dns)) {
        const f = finding(`DNS: ${dns} (中国公共 DNS)`, 'P1', '改用 8.8.8.8');
        if (f) results.push(f);
      }
    }
  }

  if (results.length === 0) {
    results.push(clean('MAC OUI 和 DNS 无中国大陆特有指纹'));
  }
  return results;
});

// ─── D6: hardware & system ──────────────────────────────────────────────────

register('hardware', '硬件与系统指纹', () => {
  const results = [];

  // DMI（WSL 中通常为空）
  // 大陆本土品牌（方正/同方/神舟等）= P2；lenovo/huawei/xiaomi 全球销售，降为 P3
  const sysVendor = readFile('/sys/class/dmi/id/sys_vendor');
  if (sysVendor !== SILENT) {
    const v = sysVendor.trim();
    if (/founder|tongfang|hasee|hasse/i.test(v)) {
      const f = finding(`DMI sys_vendor = "${v}" (大陆本土品牌)`, 'P2',
        'WSL 中 DMI 通常为空；若非空说明运行在物理机或未隔离环境');
      if (f) results.push(f);
    } else if (/lenovo|huawei|xiaomi/i.test(v)) {
      const f = finding(`DMI sys_vendor = "${v}" (国际销售的中国品牌，地理意义弱)`, 'P3',
        '该品牌全球销售，不足以判定地域');
      if (f) results.push(f);
    }
  }

  // 中文字体检测已删除 —— Noto CJK 等已非常普遍，无地理意义

  // 输入法：检测具体的中文输入法二进制/配置，而非仅环境变量
  // fcitx5-pinyin / fcitx5-rime / ibus-pinyin / ibus-rime / sogou 等
  const home = os.homedir();
  const imSignals = [];
  // fcitx5 拼音/双拼/中州韵配置
  const fcitx5Pinyin = path.join(home, '.local/share/fcitx5/pinyin');
  const fcitx5Rime = path.join(home, '.local/share/fcitx5/rime');
  if (exists(fcitx5Pinyin)) imSignals.push('fcitx5 拼音配置 (.local/share/fcitx5/pinyin)');
  if (exists(fcitx5Rime)) imSignals.push('fcitx5 rime 配置 (.local/share/fcitx5/rime)');
  // fcitx4 / sogou
  const fcitx4 = path.join(home, '.config/fcitx/profile');
  if (fcitx4 && exists(fcitx4)) {
    const p = readFile(fcitx4);
    if (p !== SILENT && /pinyin|rime|sogou|sunpinyin|googlepinyin/i.test(p)) {
      imSignals.push('fcitx 中文输入法配置 (.config/fcitx/profile)');
    }
  }
  // ibus 拼音/中州韵
  const ibusDir = path.join(home, '.config/ibus');
  if (exists(ibusDir)) {
    // 检查是否装了 ibus-pinyin / ibus-rime（dpkg 静默）
    const dpkg = sh('dpkg -l 2>/dev/null | grep -E "ibus-(pinyin|rime|sunpinyin|table-chinese)"');
    if (dpkg !== SILENT && dpkg) imSignals.push(`ibus 中文输入法: ${dpkg.split('\n')[0].slice(0, 60)}`);
  }
  // Sogou 输入法（Linux 版）
  const sogouBin = '/usr/lib/x86_64-linux-gnu/sogou';
  if (exists(sogouBin) || exists('/opt/sogoupinyin')) imSignals.push('搜狗输入法 (Linux)');
  if (imSignals.length > 0) {
    const f = finding(`检测到 ${imSignals.length} 个中文输入法: ${imSignals.join(', ')}`, 'P2',
      '卸载这些输入法: rm -rf 相关配置; unset GTK_IM_MODULE QT_IM_MODULE XMODIFIERS');
    if (f) results.push(f);
  }

  // Keyboard layout — localectl 优先，缺失则回退到配置文件
  // （精简容器里常无 localectl，但布局仍可能配在 /etc/vconsole.conf 或 /etc/default/keyboard）
  let layoutSignal = null;
  const lc = sh('localectl 2>/dev/null');
  if (lc !== SILENT && /X11 Layout:\s*(cn|zh)/i.test(lc)) {
    layoutSignal = lc.match(/X11 Layout:.*/)?.[0];
  } else {
    // /etc/vconsole.conf: KEYMAP=... (cn / zh 均为中国布局)
    const vconsole = readFile('/etc/vconsole.conf');
    if (vconsole !== SILENT) {
      const m = vconsole.match(/^\s*KEYMAP=(\S+)/m);
      if (m && /cn|zh/i.test(m[1])) layoutSignal = `vconsole KEYMAP=${m[1]}`;
    }
    // /etc/default/keyboard: XKBLAYOUT="us,cn" 等
    if (!layoutSignal) {
      const kb = readFile('/etc/default/keyboard');
      if (kb !== SILENT) {
        const m = kb.match(/^\s*XKBLAYOUT=["']?([^"'\n]+)/m);
        if (m && /\b(cn|zh)\b/i.test(m[1])) layoutSignal = `XKBLAYOUT=${m[1]}`;
      }
    }
  }
  if (layoutSignal) {
    const f = finding(`键盘布局: ${layoutSignal}`, 'P3', 'sudo localectl set-x11-keymap us');
    if (f) results.push(f);
  }

  if (results.length === 0) {
    results.push(clean('未发现中国特有硬件/系统指纹 (WSL 默认隔离良好)'));
  }
  return results;
});

// ─── D7: Claude Code config ─────────────────────────────────────────────────

register('claude-config', 'Claude Code 配置与缓存', () => {
  const results = [];
  const home = os.homedir();

  // 只检测 ANTHROPIC_BASE_URL —— 真正能证明"路由到中国后端"的是 base URL，
  // 模型名（deepseek/glm 等）谁都可能配，不构成地理判定，故不匹配整个 settings.json。
  const settings = readFile(path.join(home, '.claude/settings.json'));
  if (settings !== SILENT) {
    const urlMatch = settings.match(/"ANTHROPIC_BASE_URL"\s*:\s*"([^"]+)"/);
    if (urlMatch) {
      const url = urlMatch[1];
      const hit = matchCnProvider(url); // {kind, name} 或 null
      if (hit) {
        const label = hit.kind === 'lab' ? '中国 AI 实验室' : '中转站';
        const f = finding(`Claude Code 的 ANTHROPIC_BASE_URL 指向${label} (${hit.name}): ${url}`, 'P0',
          '修改 ANTHROPIC_BASE_URL 直连官方 API');
        if (f) results.push(f);
      } else if (/\.cn\b|\bcn-/.test(url)) {
        // 不在黑名单但含 .cn / cn- 的兜底
        const f = finding(`Claude Code 配置的 API 基址含 .cn / cn- 区域: ${url}`, 'P0',
          '修改 ANTHROPIC_BASE_URL');
        if (f) results.push(f);
      }
    }
  }

  if (results.length === 0) {
    results.push(clean('Claude Code 配置无中国 AI 实验室 API'));
  }
  return results;
});

// ─── D8: misc ───────────────────────────────────────────────────────────────

register('misc', '其他杂项', () => {
  const results = [];

  // hostname
  if (/[一-鿿]/.test(os.hostname())) {
    const f = finding(`hostname 含中文: "${os.hostname()}"`, 'P3',
      'sudo hostnamectl set-hostname <ascii>');
    if (f) results.push(f);
  }

  // machine-id
  const mid = readFile('/etc/machine-id');
  if (mid !== SILENT) {
    results.push(clean(`/etc/machine-id: ${mid.trim().slice(0, 12)}... (仅用于跨会话关联)`));
  }

  // git email domain
  const gitEmail = sh('git config --global user.email 2>/dev/null');
  if (gitEmail !== SILENT) {
    const cnEmail = ['@qq.com', '@163.com', '@126.com', '@sina.com', '@sina.cn',
                      '@139.com', '@189.cn', '@wo.cn', '@foxmail.com'];
    if (cnEmail.some(d => gitEmail.includes(d))) {
      const f = finding(`Git email: ${gitEmail} (中国邮箱)`, 'P1',
        'git config --global user.email <other>');
      if (f) results.push(f);
    }
  }

  // gitee insteadOf
  const giteeInstead = sh('git config --global url."https://gitee.com/".insteadOf 2>/dev/null');
  if (giteeInstead !== SILENT) {
    const f = finding('Git 配置了 gitee.com insteadOf', 'P1',
      'git config --global --unset url.https://gitee.com/.insteadOf');
    if (f) results.push(f);
  }

  if (results.filter(r => r.found).length === 0) {
    results.push(clean('杂项检查无异常'));
  }
  return results;
});

// ─── D9: CC Switch — the death signal ───────────────────────────────────────
//
// Severity logic:
//   CC Switch installed only              → P2 (weak: the app itself isn't proof)
//   CC Switch .db 含中转站/AI 实验室 URL    → P0 (proves API routing through CN)
//   CC Switch language = zh               → P1 (strong but could be overseas Chinese)
//   注：中国 AI 模型的*使用记录*（db 里的模型名、日志）不算特征 ——
//       谁都可能用过 deepseek/glm，不构成地理判定。

// ── 中国 AI 提供商黑名单（来自 Claude Code 二进制反混淆） ──
// D7 (Claude settings) 与 D9 (CC Switch db) 共用：判断 base URL 是否路由到中国后端。
const CN_AI_LABS = [
  'deepseek', 'moonshot', 'minimax', 'xaminim',
  'zhipu', 'bigmodel', 'baichuan', 'stepfun',
  '01ai', 'dashscope', 'volces',
];

const CN_PROXY_DOMAINS = [
  'sankuai.com', 'netease.com', '163.com', 'baidu-int.com',
  'baidu.com', 'alibaba-inc.com', 'alipay.com', 'antgroup-inc.cn',
  'kuaishou.com', 'bytedance.net', 'xiaohongshu.com', 'ctripcorp.com',
  'jd.com', 'jdcloud.com', 'bilibili.co', 'iflytek.com',
  'stepfun-inc.com', 'aliyuncs.com', 'cn-shanghai.fcapp.run',
  'cn-beijing.fcapp.run', 'xaminim.com', 'moonshot.ai',
  'anyrouter.top', 'packyapi.com', 'aicodemirror.com', 'aigocode.com',
  'hongshan.com', 'iwhalecloud.com', 'dhcoder.net', 'lemongpt.top',
  'zhihuiapi.top', 'intsig.net', 'high-five-ai.xyz', 'cloudsway.net',
  '4sapi.com', '529961.com', '88996.cloud', '88code.ai', '88code.org',
  '91code.pro', '992236.xyz', 'ai.codeqaq.com', 'ai.hybgzs.com',
  'ai.kjvhh.com', 'aicanapi.com', 'aicoding.sh', 'aifast.site',
  'aihubmix.com', 'anmory.com', 'api.5202030.xyz', 'api.ablai.top',
  'api.bianxie.ai', 'api.bltcy.ai', 'api.cpass.cc', 'api.dev88.tech',
  'api.dreamger.com', 'api.expansion.chat', 'api.gueai.com',
  'api.holdai.top', 'api.ikuncode.cc', 'api.lconai.com',
  'api.linkapi.org', 'api.mkeai.com', 'api.nekoapi.com',
  'api.oaipro.com', 'api.ruyun.fun', 'api.ssopen.top', 'api.tu-zi.com',
  'api.uglycat.cc', 'api.v3.cm', 'api.whatai.cc', 'api.wpgzs.top',
  'api.xty.app', 'api.yuegle.com', 'api.zzyu.me', 'apimart.ai',
  'apipro.maynor1024.live', 'apiyi.com', 'applyj.hiapi.top',
  'augmunt.com', 'b4u.qzz.io', 'clauddy.com', 'claude-code-hub.app',
  'claude-opus.top', 'claudeide.net', 'co.yes.vg', 'code.wenwen-ai.com',
  'code.x-aio.com', 'codeilab.com', 'cubence.com', 'deeprouter.top',
  'dimaray.com', 'dmxapi.com', 'docs.aigc2d.com', 'duckcoding.com',
  'fk.hshwk.org', 'flapcode.com', 'foxcode.hshwk.org', 'foxcode.rjj.cc',
  'fuli.hxi.me', 'getgoapi.com', 'gpt.zhizengzeng.com', 'gptgod.cloud',
  'gptkey.eu.org', 'gptpay.store', 'hdgsb.com', 'henapi.top',
  'instcopilot-api.com', 'jeniya.top', 'jiekou.ai', 'kg-api.cloud',
  'n1n.ai', 'new-api.u4vr.com', 'new.xychatai.com', 'one-api.bltcy.top',
  'one.ocoolai.com', 'oneapi.paintbot.top', 'open.xiaojingai.com',
  'openclaude.me', 'opus.gptuu.com', 'poloai.top', 'poloapi.top',
  'privnode.com', 'proxyai.com', 'qinzhiai.com', 'right.codes',
  'runanytime.hxi.me', 'sssaicode.com', 'store.zzyus.top',
  'tiantianai.pro', 'uiuiapi.com', 'uniapi.ai', 'vip.undyingapi.com',
  'wolfai.top', 'wzw.de5.net', 'wzw.pp.ua', 'xairouter.com',
  'xaixapi.com', 'xiaohuapi.site', 'xiaohumini.site', 'xy.poloapi.com',
  'yansd666.com', 'yansd666.top', 'yunwu.ai', 'yunwu.zeabur.app',
  'zenmux.ai',
];

/**
 * 判断一个 base URL 是否路由到中国后端。
 * @returns {{kind:'lab'|'proxy', name:string} | null}
 *   lab  = 命中中国 AI 实验室名；proxy = 命中中转站域名；null = 非中国。
 *   实验室优先于中转站（实验室是更具体的强信号）。
 */
function matchCnProvider(url) {
  const u = url.toLowerCase();
  for (const lab of CN_AI_LABS) {
    if (u.includes(lab)) return { kind: 'lab', name: lab };
  }
  for (const domain of CN_PROXY_DOMAINS) {
    if (u.includes(domain)) return { kind: 'proxy', name: domain };
  }
  return null;
}

register('cc-switch', 'CC Switch (AI 工具管理器)', () => {
  const results = [];
  const users = windowsUsers();

  let hasInstallation = false;
  let hasCnLabProvider = false;
  let hasCnProxyProvider = false;
  const cnProviders = []; // 所有指向中国后端的 base URL（去重）

  // ── Scan each Windows user ──────────────────────────────────────────────

  for (const user of users) {
    const ccExe = `/mnt/c/Users/${user}/AppData/Local/Programs/CC Switch/cc-switch.exe`;
    const ccDb  = `/mnt/c/Users/${user}/.cc-switch/cc-switch.db`;
    const ccSet = `/mnt/c/Users/${user}/.cc-switch/settings.json`;

    // ── 9.1 Installation (P2 — just having the app isn't proof) ─────────

    if (exists(ccExe)) {
      hasInstallation = true;
      const f = finding(`CC Switch 已安装: ${ccExe}`, 'P2',
        '仅安装不足以判定。关键看数据库中的提供商配置。');
      if (f) results.push(f);
    }

    // ── 9.2 Database: 提取所有 base URL，收集指向中国后端者 ──────────────

    if (exists(ccDb)) {
      try {
        const dbStr = fs.readFileSync(ccDb).toString('utf-8');

        const urlSet = new Set();
        const re1 = /"ANTHROPIC_BASE_URL"\s*:\s*"([^"]+)"/g;
        const re2 = /"base_url"\s*:\s*"([^"]+)"/gi;
        let m;
        while ((m = re1.exec(dbStr)) !== null) urlSet.add(m[1]);
        while ((m = re2.exec(dbStr)) !== null) urlSet.add(m[1]);

        for (const url of urlSet) {
          const hit = matchCnProvider(url);
          if (!hit) continue;
          if (hit.kind === 'lab') hasCnLabProvider = true;
          else hasCnProxyProvider = true;
          const label = hit.kind === 'lab' ? '实验室' : '中转站';
          cnProviders.push(`${label} ${hit.name}: ${url}`);
        }

      } catch { /* DB parse failure */ }
    }

    // ── 9.3 Settings (language = zh is P1, not P0) ──────────────────────

    if (exists(ccSet)) {
      const raw = readFile(ccSet);
      if (raw !== SILENT) {
        try {
          const cfg = JSON.parse(raw);

          if (cfg.language === 'zh') {
            const f = finding('CC Switch 界面语言: "zh" (中文)', 'P1',
              'CC Switch 设置中改为 English。但此信号本身不构成判定 — 海外华人也会用中文界面。');
            if (f) results.push(f);
          }
        } catch { /* parse error */ }
      }
    }
  }

  // ── Summary verdict ────────────────────────────────────────────────────

  if (!hasInstallation) {
    results.push(clean('未检测到 CC Switch 安装'));
  } else if (cnProviders.length === 0) {
    // Installed but clean — only managing official APIs
    results.push(clean('CC Switch 已安装但未检测到中转站或中国 AI 实验室提供商'));
  }

  // 把所有指向中国后端的提供商合并成一条 P0
  if (cnProviders.length > 0) {
    const list = cnProviders.slice(0, 6).join(' | ') + (cnProviders.length > 6 ? ' …' : '');
    const f = finding(`CC Switch 配置了 ${cnProviders.length} 个指向中国后端的提供商: ${list}`,
      'P0', '卸载 CC Switch，从 cc-switch.db 删除这些提供商，改用 Claude Code settings.json 直连官方 API');
    if (f) results.push(f);
  }

  return results;
});

// ─── D10: AxonHub — AI Gateway ──────────────────────────────────────────────
//
// 分级：AxonHub 是中国开发者 (looplj) 创建的 AI 网关。但"装了/在跑/配置指向它"
// 本身只是运行特征，与 CC Switch 的"已安装"对齐 → 一律 P2。
// 不检测"是否运行"（与"已安装"重复）；也不把"用过中国模型"当特征。

register('axonhub', 'AxonHub (AI 代理网关)', () => {
  const results = [];
  const home = os.homedir();

  // 10.1 Claude Code settings.json 指向 AxonHub（使用特征 → P2）
  const ccSettings = readFile(path.join(home, '.claude/settings.json'));
  if (ccSettings !== SILENT) {
    // AxonHub default port 8090 + /anthropic suffix
    if (/localhost:8090\/anthropic|127\.0\.0\.1:8090\/anthropic/.test(ccSettings)) {
      const f = finding('Claude Code 配置指向 AxonHub: localhost:8090/anthropic', 'P2',
        'AxonHub 是中国开发者创建的 AI 网关');
      if (f) results.push(f);
    }

    // AxonHub API key prefix: "ah" (vs Anthropic "sk-")
    const tokenMatch = ccSettings.match(/"ANTHROPIC_AUTH_TOKEN"\s*:\s*"([^"]+)"/);
    if (tokenMatch && /^ah/i.test(tokenMatch[1])) {
      const f = finding('Claude Code 使用 AxonHub API Key (ah 前缀)', 'P2',
        'ah 前缀是 AxonHub 的密钥格式标识');
      if (f) results.push(f);
    }

    // Generic: non-standard anthropic base URL on localhost (common for gateways)
    const baseUrlMatch = ccSettings.match(/"ANTHROPIC_BASE_URL"\s*:\s*"([^"]+)"/);
    if (baseUrlMatch) {
      const url = baseUrlMatch[1];
      // Check for common gateway ports
      if (/localhost:\d{4}\/anthropic/.test(url) && !/8090/.test(url)) {
        const f = finding(`Claude Code 经本地代理网关: ${url} (疑似 AxonHub 或同类)`, 'P2',
          '确认是否为 AxonHub/CC Switch 等代理工具');
        if (f) results.push(f);
      }
    }
  }

  // 10.2 Check for AxonHub binary
  const binaryPaths = [
    '/usr/local/bin/axonhub',
    path.join(home, '.local/bin/axonhub'),
    '/opt/axonhub/axonhub',
    '/usr/bin/axonhub',
    // Windows (via /mnt/c/)
    ...(MNT_C ? (() => {
      const firstUser = windowsUsers()[0];
      const paths = ['/mnt/c/axonhub.exe'];
      if (firstUser) paths.unshift(`/mnt/c/Users/${firstUser}/axonhub.exe`);
      return paths;
    })() : []),
  ];
  for (const bp of binaryPaths) {
    if (exists(bp)) {
      const f = finding(`AxonHub 二进制: ${bp}`, 'P2', `删除 ${bp}`);
      if (f) results.push(f);
      break;
    }
  }

  // 10.3 (已删除) 进程运行检测 —— 与"已安装"重复，无独立地理意义

  // 10.4 axonhub.db
  const dbPaths = [
    path.join(home, 'axonhub.db'),
    '/opt/axonhub/axonhub.db',
    '/var/lib/axonhub/axonhub.db',
    '/tmp/axonhub.db',
  ];
  for (const dp of dbPaths) {
    if (exists(dp)) {
      const sizeMB = (statSize(dp) / 1048576).toFixed(1);
      const f = finding(`AxonHub 数据库: ${dp} (${sizeMB} MB)`, 'P2',
        `删除 ${dp}`);
      if (f) results.push(f);
      break;
    }
  }
  // Also search home directory recursively (shallow, max depth 3)
  const findDb = sh(`find ${home} -maxdepth 3 -name "axonhub.db" 2>/dev/null`);
  if (findDb !== SILENT && findDb) {
    for (const p of findDb.split('\n').filter(Boolean)) {
      if (!dbPaths.includes(p)) {
        const f = finding(`AxonHub 数据库: ${p}`, 'P2', `删除 ${p}`);
        if (f) results.push(f);
      }
    }
  }

  // 10.5 Check for AxonHub config.yml
  const cfgPaths = [
    path.join(home, 'axonhub/config.yml'),
    path.join(home, 'axonhub/config.yaml'),
    '/etc/axonhub/config.yml',
    '/opt/axonhub/config.yml',
  ];
  for (const cp of cfgPaths) {
    const cfgContent = readFile(cp);
    if (cfgContent !== SILENT) {
      // AxonHub-specific config keys
      if (/claude_code_trace_enabled|provider_quota|axonhub\.db/i.test(cfgContent)) {
        const f = finding(`AxonHub 配置文件: ${cp}`, 'P2',
          'AxonHub 特色配置: claude_code_trace_enabled, provider_quota');
        if (f) results.push(f);
        break;
      }
    }
  }

  // 10.6 Check logs
  const logPaths = [
    path.join(home, 'axonhub/logs/axonhub.log'),
    '/opt/axonhub/logs/axonhub.log',
    '/var/log/axonhub.log',
  ];
  for (const lp of logPaths) {
    if (exists(lp)) {
      const f = finding(`AxonHub 日志: ${lp}`, 'P2', `删除 ${lp}`);
      if (f) results.push(f);
      break;
    }
  }

  // 10.7 Docker（镜像存在即安装特征；不再单独查"运行中容器"——与镜像重复）
  const dockerImg = sh('docker images 2>/dev/null | grep axonhub');
  if (dockerImg !== SILENT && dockerImg) {
    const f = finding(`AxonHub Docker 镜像存在: ${dockerImg.slice(0, 100)}`, 'P2',
      'docker rmi <image>');
    if (f) results.push(f);
  }

  // 10.8 systemd service
  const systemd = sh('systemctl list-units --type=service 2>/dev/null | grep axonhub');
  if (systemd !== SILENT && systemd) {
    const f = finding('AxonHub systemd 服务已注册', 'P2',
      'sudo systemctl disable --now axonhub');
    if (f) results.push(f);
  }

  // 10.9 npm @axhub/genie (Web UI for AxonHub)
  const npmAxon = sh('npm list -g 2>/dev/null | grep @axhub/genie');
  if (npmAxon !== SILENT && npmAxon) {
    const f = finding('npm 已安装 @axhub/genie (AxonHub Web UI)', 'P2',
      'npm uninstall -g @axhub/genie');
    if (f) results.push(f);
  }

  // 10.10 ENV vars with AXONHUB_ prefix
  for (const [k, v] of Object.entries(process.env)) {
    if (k.startsWith('AXONHUB_')) {
      const f = finding(`环境变量 ${k}=${v} (AxonHub 配置)`, 'P2', `unset ${k}`);
      if (f) results.push(f);
    }
  }

  // 10.11 Check for AxonHub Helm release (K8s)
  const helmList = sh('helm list 2>/dev/null | grep axonhub');
  if (helmList !== SILENT && helmList) {
    const f = finding('Kubernetes 中部署了 AxonHub (Helm release)', 'P2',
      'helm uninstall axonhub');
    if (f) results.push(f);
  }

  if (results.filter(r => r.found).length === 0) {
    results.push(clean('未检测到 AxonHub 安装或使用痕迹'));
  }

  return results;
});

// ─── D11: WSL-specific ──────────────────────────────────────────────────────

register('wsl-signals', 'WSL 特有信号', () => {
  const results = [];

  if (IS_WSL) {
    // WSL interop: can we call Windows binaries directly?
    const wslInterop = process.env.WSL_INTEROP;
    const canExecExe = sh('which cmd.exe 2>/dev/null') !== SILENT;

    if (canExecExe) {
      // This means Claude Code could also exec Windows binaries
      results.push(clean('WSL interop 可用 (可执行 Windows 二进制) — 可用于调用 reg.exe / powershell.exe 获取系统信息'));
    }

    // WSLg — can access Windows GUI
    if (process.env.WSL2_GUI_APPS_ENABLED) {
      results.push(clean('WSLg 已启用 — 可运行 Windows GUI 应用'));
    }

    // Check for NVIDIA GPU passthrough (not geo-specific, but hardware info)
    if (exists('/usr/lib/wsl/lib/nvidia-smi')) {
      results.push(clean('NVIDIA GPU passthrough 可用 (非地理信号，仅硬件信息)'));
    }
  }

  return results;
});

// ─── main runner ─────────────────────────────────────────────────────────────

function runAll() {
  DEDUP.clear();
  const allResults = [];
  for (const { id, label, run } of detectors) {
    let checks;
    try {
      checks = run();
    } catch (e) {
      checks = [{ found: false, evidence: `检测器异常: ${e.message}`, severity: 'P3', solution: '' }];
    }
    allResults.push({ id, label, checks });
  }
  return allResults;
}

function formatResults(allResults) {
  if (JSON_MODE) {
    const flat = allResults.flatMap(r => r.checks).filter(c => c.found);
    return JSON.stringify({
      verdict: flat.length > 0 ? 'CHINESE_DETECTED' : 'CLEAN',
      platform: IS_WSL ? 'wsl2' : 'linux',
      mntAccessible: MNT_C,
      totalSignals: flat.length,
      bySeverity: {
        P0: flat.filter(c => c.severity === 'P0').length,
        P1: flat.filter(c => c.severity === 'P1').length,
        P2: flat.filter(c => c.severity === 'P2').length,
        P3: flat.filter(c => c.severity === 'P3').length,
      },
      modules: allResults.map(r => ({
        module: r.id, label: r.label, signals: r.checks.filter(c => c.found).length,
        details: r.checks.filter(c => c.found),
        ...(DEBUG ? { clean: r.checks.filter(c => !c.found).map(c => c.evidence) } : {}),
      })),
    }, null, 2);
  }

  const flat = allResults.flatMap(r => r.checks);
  const found = flat.filter(c => c.found);
  const total = DEMO_CLEAN ? 0 : found.length; // --demo-clean 强制走 CLEAN 分支

  let out = '\n';

  // ── SUMMARY MODE ──────────────────────────────────────────────────────────
  if (SUMMARY) {
    if (total > 0) {
      out += `${R}${B}检测到中国人 — ${total} 个信号${X}\n`;
      const p0 = found.filter(c => c.severity === 'P0').length;
      out += `P0(致命):${p0} P1(严重):${found.filter(c=>c.severity==='P1').length} P2:${found.filter(c=>c.severity==='P2').length} P3:${found.filter(c=>c.severity==='P3').length}\n`;
      out += `/mnt/c/: ${MNT_C ? R+'可访问'+X : G+'已禁用'+X}\n`;
      if (p0 > 0) out += `${R}结论: 存在被服务端通过客户端隐写识别的地域风险${X}\n`;
    } else {
      out += `${G}${B}未检测到中国大陆指纹${X}\n`;
    }
    out += '\n';
    return out;
  }

  // ── FULL OUTPUT ───────────────────────────────────────────────────────────

  if (total > 0) {
    out += R + B;
    out += '╔═════════════════════════════════════════╗\n';
    out += '║         ⚠  检 测 到 中 国 人  ⚠         ║\n';
    out += '╚═════════════════════════════════════════╝\n';
    out += X;
    out += `\n${B}共发现 ${R}${total}${X}${B} 个信号${X}\n\n`;

    for (const { id, label, checks } of allResults) {
      const positives = checks.filter(c => c.found);
      const cleans = checks.filter(c => !c.found);
      if (positives.length === 0 && !(DEBUG && cleans.length > 0)) continue;

      out += `${B}${C}▸ ${label}${X} ${R}(${positives.length} 个)${X}\n`;
      out += `${D}${'─'.repeat(60)}${X}\n`;

      for (const c of positives) {
        const sc = c.severity === 'P0' ? R : c.severity === 'P1' ? Y : D;
        out += `  ${sc}[${c.severity}]${X} ${c.evidence}\n`;
        if (c.solution) {
          out += `  ${D}→ 建议:${X} ${c.solution}\n`;
        }
        out += '\n';
      }

      // ── debug：展示该检测器未命中的检查项 ──
      if (DEBUG && cleans.length > 0) {
        out += `  ${D}✓ 未命中 (${cleans.length}):${X}\n`;
        for (const c of cleans) {
          out += `  ${D}  · ${c.evidence}${X}\n`;
        }
        out += '\n';
      }
    }

    out += `${B}${'─'.repeat(60)}${X}\n`;
    const p0 = found.filter(c => c.severity === 'P0').length;
    const p1 = found.filter(c => c.severity === 'P1').length;
    const p2 = found.filter(c => c.severity === 'P2').length;
    const p3 = found.filter(c => c.severity === 'P3').length;
    out += `${B}严重程度:${X} ${R}P0(致命):${p0}${X} ${Y}P1(严重):${p1}${X} ${D}P2:${p2} P3:${p3}${X}\n`;
    out += `${B}/mnt/c/:${X} ${MNT_C ? R + '可访问 ⚠' + X : G + '已禁用 ✓' + X}\n`;
    out += `\n${D}/etc/wsl.conf 中 [automount] enabled=false 可阻断 90%+ 指纹信号源，但会破坏 VS Code Remote WSL 和 /mnt/c/ 交互等各种功能。${X}\n`;

    if (p0 > 0) {
      out += `\n${R}${B}结论: 存在被服务端通过客户端隐写手段识别的地域风险。此为基于公开逆向资料的技术推测。${X}\n`;
    }

    out += `\n${D}所有检查均为 fs.readdirSync / fs.readFileSync / process.env 程序化操作，均可被 XOR-混淆嵌入二进制。${X}\n`;
    out += `${D}程序不联网，结果不上传。${X}\n`;

  } else {
    // ── CLEAN ───────────────────────────────────────────────────────────────
    out += G + B;
    out += '╔════════════════════════════════════════════╗\n';
    out += '║        ✨  未检测到中国大陆指纹  ✨        ║\n';
    out += '╚════════════════════════════════════════════╝\n';
    out += X;
    out += '\n本机未命中任何已知指纹。\n';
    out += `${D}注意: 以上检测基于已公开的第三方逆向分析资料，不代表任何机构的实际行为。${X}\n`;
    out += '\n';

    out += `${B}检测覆盖:${X}\n`;
    for (const { label, checks } of allResults) {
      const allClean = checks.every(c => !c.found);
      out += `  ${allClean ? G + '✓' + X : ' '} ${label}\n`;
    }
    out += '\n';

    // ── debug：clean 机器也展示各检测器未命中的检查项 ──
    if (DEBUG) {
      for (const { label, checks } of allResults) {
        const cleans = checks.filter(c => !c.found);
        if (cleans.length === 0) continue;
        out += `${B}${C}▸ ${label}${X} ${G}(全部未命中)${X}\n`;
        out += `${D}${'─'.repeat(60)}${X}\n`;
        for (const c of cleans) {
          out += `  ${D}· ${c.evidence}${X}\n`;
        }
        out += '\n';
      }
    }
  }

  out += `${D}平台: ${IS_WSL ? 'WSL2' : 'Linux'} | /mnt/c/: ${MNT_C ? '已挂载' : '未挂载'} | MisAnthropic v2.0.0${X}\n`;
  out += '\n';
  return out;
}

// ─── entry ───────────────────────────────────────────────────────────────────

if (FIX_MODE) {
  console.log(`
${B}修复指南 — MisAnthropic v2.0.0${X}

${B}最快见效的三步:${X}
  1. wsl.conf 禁用 automount:    [automount]\\nenabled=false
  2. 清理 Shell 历史:            history -c && rm ~/.bash_history ~/.zsh_history
  3. 时区改为非中国:              sudo timedatectl set-timezone Asia/Singapore

${B}包管理器:${X}
  npm config set registry https://registry.npmjs.org/
  npm cache clean --force
  检查 ~/.pip/pip.conf ~/.cargo/config.toml ~/.docker/config.json
  检查 /etc/apt/sources.list

${B}Windows 端: (如果曾挂载 /mnt/c/)${X}
  删除 PowerShell 历史:  %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\
  删除 WiFi 历史:        C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\
  删除 Public Desktop 中文快捷方式
  卸载 CC Switch 并删除 C:\\Users\\<user>\\.cc-switch\\
`);
  process.exit(0);
}

const data = runAll();
console.log(formatResults(data));
