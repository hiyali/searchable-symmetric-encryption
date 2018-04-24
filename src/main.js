import aesjs from 'aes-js'
import CryptoJS from 'crypto-js'
import randomize from 'randomatic'
import spritzjs from 'spritzjs'
import bitwise from 'bitwise'

import bcrypt from 'bcryptjs'
import { argv } from 'yargs'

import Log from './log.js'
import { CONSTANT_N, CONSTANT_M, KEY_LENGTH } from './constants.js'

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
  Log('K2', K2_str)
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
  Log('Wi', Wi_str)
  const Wi = aesjs.utils.utf8.toBytes(Wi_str)

  /*
   * 4. CBC - Cipher-Block Chaining 分组密码 （同：块加密）
   */
  aesCbc = new aesjs.ModeOfOperation.cbc(K2, IV)
  const X_bytes = aesCbc.encrypt(Wi)
  const X = aesjs.utils.hex.fromBytes(X_bytes) // 打印或者存储以上加密的分组流之前，需要转换成 16 进制
  Log('X', X)

  /*
   * 5. X 一分为二，得到：Li , Ri
   */
  const Li = X.slice(0, (CONSTANT_N - CONSTANT_M) * 2)
  const Ri = X.slice((CONSTANT_N - CONSTANT_M) * 2, CONSTANT_N * 2)
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

  const Si_bytes = spritz.hash(Seeds, CONSTANT_N - CONSTANT_M)
  const Si = aesjs.utils.hex.fromBytes(Si_bytes)
  Log('Si', Si)

  /*
   * 8. 用 SHA1 / K1 来加密得到：Ki
   */
  const Ki = CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA1(Li, K1))
  // const Ki = CryptoJS.PBKDF2(Li, K1, { keySize: 128 / 32 })
  Log('Ki', Ki)
  // console.log(Ki)

  /*
   * 9. 用 MD5 /Ki 来加密：Si
   */
  const FKiSi = CryptoJS.enc.Hex.stringify(CryptoJS.HmacMD5(Si, Ki))
  Log('FKiSi', FKiSi)

  /*
   * 10. 模2加法（异或运算）X 与 <Si, FKiSi> 得到：Ci
   */
  const FKiSi_buffer = Buffer.from(FKiSi, 'hex')
  const FKiSi_bits = bitwise.buffer.read(FKiSi_buffer)
  const X_buffer = Buffer.from(X, 'hex')
  const X_bits = bitwise.buffer.read(X_buffer)
  const Ci_bits = bitwise.bits.xor(X_bits, FKiSi_bits)
  const Ci_bytes = []
  for (let i = 0; i < Ci_bits.length; i += 8) {
    const byte = bitwise.byte.write(Ci_bits.slice(i, i + 8))
    Ci_bytes.push(byte)
  }
  Ci = aesjs.utils.hex.fromBytes(Ci_bytes)
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
  Log('W', W_str)
  const W = aesjs.utils.utf8.toBytes(W_str)

  /*
   * 2. CBC - Cipher-Block Chaining 分组密码 （同：块加密）
   */
  const X_bytes = aesCbc.encrypt(W) // from K2
  const X = aesjs.utils.hex.fromBytes(X_bytes) // 打印或者存储以上加密的分组流之前，需要转换成 16 进制
  Log('X', X)

  /*
   * 3. X 一分为二，得到：L , R
   */
  const L = X.substr(0, (CONSTANT_N - CONSTANT_M) * 2)
  const R = X.substr((CONSTANT_N - CONSTANT_M) * 2, CONSTANT_N * 2)
  Log('L / R', L + '/' + R)

  /*
   * 4. 用 SHA1 来加密 L/K1 得到：K
   */
  const K = CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA1(L, K1))
  // const K = CryptoJS.PBKDF2(L, K1, { keySize: 128 / 32 })
  Log('K', K)
  // console.log(K)

  /*
   * 5. <X, k>
   */
  XK_list = [X, K]
  Log('<X, K>', XK_list)
})()



;(async () => {
  Log('\nSSE实践 ... 第三步', '', {
    titleColor: 'cyan'
  })

  /*
   * 1. 取出 X, K 两个参数
   */
  const X = XK_list[0]
  Log('X', X)
  const K = XK_list[1]
  Log('K', K)

  /*
   * 2. 在 Ci 与 X 的比特流上做模二加法运算 XOR: Si
   */
  const X_buffer = Buffer.from(X, 'hex')
  const X_bits = bitwise.buffer.read(X_buffer)

  const Ci_buffer = Buffer.from(Ci, 'hex')
  const Ci_bits = bitwise.buffer.read(Ci_buffer)

  const Si_bits = bitwise.bits.xor(Ci_bits, X_bits)
  const Si_bytes = []
  for (let i = 0; i < Si_bits.length; i += 8) {
    const byte = bitwise.byte.write(Si_bits.slice(i, i + 8))
    Si_bytes.push(byte)
  }
  const Si = aesjs.utils.hex.fromBytes(Si_bytes)
  Log('Si', Si)

  /*
   * 3. 用 MD5 /K 来加密：Si
   */
  const Fi = CryptoJS.HmacMD5(Si, K)
  Log('Fi', Fi)
})()



/*
;(async () => {
  Log('\nSSE实践 ... 解密实验', '', {
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
