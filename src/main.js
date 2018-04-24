import aesjs from 'aes-js'
import bcrypt from 'bcryptjs'
import CryptoJS from 'crypto-js'
import randomize from 'randomatic'
import spritzjs from 'spritzjs'
import { argv } from 'yargs'

import Log from './log.js'
import { HEX_ARR_XOR, STR_HEX_XOR } from './utils.js'
import { KEY_LENGTH } from './constants.js'

const spritz = spritzjs()

let K1
let K2

let IV
let aesCbc

let Ci
let XK_list

;(async () => {
  Log('SSE实践开始 ... 第一步', '', {
    titleColor: 'cyan'
  })

  /*
   * 1. 生成：密钥 K"
   */
  const K2_str = randomize('Aa0!', KEY_LENGTH)
  Log('K2_str', K2_str)
  K2 = aesjs.utils.utf8.toBytes(K2_str)

  /*
   * 2. 生成：分组加密所需的向量 IV (initialization vector)
   * 解释：
   * 需协商一个初始化向量（IV），这个IV没有实际意义，只是在第一次计算的时候需要用到而已。
   * 采用这种模式的话安全性会有所提高。
   */
  const IV_str = randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
  IV = aesjs.utils.utf8.toBytes(IV_str)

  /*
   * 3. 接收输入的文字或生成：纯字符串 Wi
   */
  const Wi_str = 'constant-string1' || randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
  Log('Wi_str', Wi_str)
  const Wi = aesjs.utils.utf8.toBytes(Wi_str)

  /*
   * 4. CBC - Cipher-Block Chaining 分组密码 （同：块加密）
   */
  aesCbc = new aesjs.ModeOfOperation.cbc(K2, IV)
  const X = aesCbc.encrypt(Wi)
  const X_hex = aesjs.utils.hex.fromBytes(X) // 打印或者存储以上加密的分组流之前，需要转换成 16 进制
  Log('X_hex', X_hex)

  /*
   * 5. X 一分为二，得到：Li , Ri
   */
  const halfLength = Math.round(X_hex.length / 2) // X 的一半（四舍五入）
  const Li = X_hex.slice(0, halfLength)
  const Ri = X_hex.slice(halfLength, X_hex.length)
  Log('Li / Ri', Li + '/' + Ri)

  /*
   * 6. 生成：密钥 K'
   */
  K1 = randomize('Aa0!', KEY_LENGTH)
  Log('K1', K1)

  /*
   * 7. Stream-Cipher RC4-like hash：Si
   */
  const Seeds_str = 'seeds' || randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
  const Seeds = aesjs.utils.utf8.toBytes(Seeds_str)

  const Si_bytes = spritz.hash(Seeds, KEY_LENGTH)
  const Si = aesjs.utils.hex.fromBytes(Si_bytes)
  Log('Si', Si)

  /*
   * 8. 用 MD5 / K1 来加密得到：Ki
   */
  const Ki = CryptoJS.HmacMD5(Li, K1)
  Log('Ki', Ki)

  /*
   * 9. 用 MD5 /Ki 来加密：Si
   */
  const FKiSi_str = CryptoJS.HmacMD5(Si, Ki)
  Log('FKiSi_str', FKiSi_str)
  const FKiSi = aesjs.utils.utf8.toBytes(FKiSi_str)

  /*
   * 10. 模2加法（异或运算）X 与 FKiSi 得到：Ci
   */
  Ci = HEX_ARR_XOR(X, Si_bytes.concat(FKiSi))
  Log('Ci', Ci)


  /*
   *
   * 后期用来传参
   *
   *
  let inputText = argv.text // 输入的文字
  Log('inputText', inputText)
  if (typeof inputText === 'string') {
    inputText = inputText.substr(0, KEY_LENGTH) // 截取输入的文字的 前 16 位
    inputText = inputText.padEnd(KEY_LENGTH, '0') // 用字符0填充不到 16 位的字符串
  }
  // */
})()



;(async () => {
  Log('\nSSE实践 ... 第二步', '', {
    titleColor: 'cyan'
  })

  /*
   * 1. 接收输入的文字或生成：纯字符串 W
   */
  const W_str = 'constant-string1' || randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
  Log('W_str', W_str)
  const W = aesjs.utils.utf8.toBytes(W_str)

  /*
   * 2. CBC - Cipher-Block Chaining 分组密码 （同：块加密）
   */
  const X = aesCbc.encrypt(W) // from K2
  const X_hex = aesjs.utils.hex.fromBytes(X) // 打印或者存储以上加密的分组流之前，需要转换成 16 进制
  Log('X_hex', X_hex)

  /*
   * 3. X 一分为二，得到：L , R
   */
  const halfLength = Math.round(X_hex.length / 2) // X 的一半（四舍五入）
  const L = X_hex.substr(0, halfLength)
  const R = X_hex.substr(halfLength, X_hex.length)
  Log('L / R', L + '/' + R)

  /*
   * 4. 用 MD5 来加密 L/K1 得到：K
   */
  const K = CryptoJS.HmacMD5(L, K1)
  Log('K', K)

  /*
   * 5. <X, k>
   */
  XK_list = [X_hex, K]
  Log('<X, K> XK_list', XK_list)
})()



;(async () => {
  Log('\nSSE实践 ... 第三步', '', {
    titleColor: 'cyan'
  })

  /*
   * 1. 取出 X, K 两个参数
   */
  const X_hex = XK_list[0]
  Log('X_hex', X_hex)
  const K = XK_list[1]
  Log('K', K)
  const X = aesjs.utils.hex.toBytes(X_hex)

  /*
   * 2. Ci 与 X 做模二运算 XOR: Si
   */
  const Ci_bytes = aesjs.utils.hex.toBytes(Ci)
  const Si = HEX_ARR_XOR(Ci_bytes, X)
  Log('Si', Si)

  /*
   * 3. 用 MD5 /K 来加密：Si
   */
  const Fi = CryptoJS.HmacMD5(Si, K)
  Log('Fi', Fi)
})()



/*
;(async () => {
  Log('\nSSE实践 ... 重新来', '', {
    titleColor: 'cyan'
  })

  const password = 'password-1'
  const salt = bcrypt.genSaltSync(10)
  const hashed = bcrypt.hashSync(password, salt)

  // const k = hashed
  const kPrime = hashed
  Log('kPrime', kPrime)

  const iv_str = randomize('Aa0!', KEY_LENGTH)
  const iv = aesjs.utils.utf8.toBytes(iv_str)
  const key_str = kPrime.substr(0, KEY_LENGTH)
  const key = aesjs.utils.utf8.toBytes(key_str)
  const cipher = new aesjs.ModeOfOperation.cbc(key, iv)

  const plainText_str = 'plain-text-1xxxx' // pad with x
  const plainText = aesjs.utils.utf8.toBytes(plainText_str)
  Log('plainText_str', plainText_str)
  const encrypted = cipher.encrypt(plainText)
  const encrypted_hex = aesjs.utils.hex.fromBytes(encrypted)
  const outFile = iv_str + encrypted_hex
  Log('outFile', outFile)

  const IV_str = outFile.substr(0, KEY_LENGTH)
  const IV = aesjs.utils.utf8.toBytes(IV_str)

  const CIPHER = new aesjs.ModeOfOperation.cbc(key, IV)
  const ENCRYPTED_hex = outFile.substr(KEY_LENGTH, outFile.length)
  Log('ENCRYPTED_hex', ENCRYPTED_hex)
  const ENCRYPTED = aesjs.utils.hex.toBytes(ENCRYPTED_hex)
  const DECRYPTED = CIPHER.decrypt(ENCRYPTED)
  const DECRYPTED_str = aesjs.utils.utf8.fromBytes(DECRYPTED)
  Log('DECRYPTED_str', DECRYPTED_str)
})()

// */
