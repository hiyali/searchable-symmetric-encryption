import aesjs from 'aes-js'
import spritzjs from 'spritzjs'
import { Crypto } from 'ezcrypto'
import randomize from 'randomatic'
import { argv } from 'yargs'

import Log from './log.js'
import { HEX_ARR_XOR } from './utils.js'
import { KEY_LENGTH } from './constants.js'

const sprit = spritzjs()
Log('SSE实践 ... 第二步', '', {
  titleColor: 'cyan'
})

/*
 * 1. 生成：密钥 K"
 */
const K2_str = randomize('Aa0!', KEY_LENGTH) // ex: => 'LV3u~BSGhw'
Log('K2_str', K2_str)
const K2 = aesjs.utils.utf8.toBytes(K2_str)

/*
 * 2. 生成：分组加密所需的向量 IV (initialization vector)
 * 解释：
 * 需协商一个初始化向量（IV），这个IV没有实际意义，只是在第一次计算的时候需要用到而已。
 * 采用这种模式的话安全性会有所提高。
 */
const IV_str = randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
const IV = aesjs.utils.utf8.toBytes(IV_str)

/*
 * 3. 接收输入的文字或生成：纯字符串 W
 */
const W_str = randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
const W = aesjs.utils.utf8.toBytes(W_str)
Log('W_str', W_str)

/*
 * 4. CBC - Cipher-Block Chaining 分组密码 （同：块加密）
 */
const aesCbc = new aesjs.ModeOfOperation.cbc(K2, IV)
const encryptedBytes = aesCbc.encrypt(W)
const X = aesjs.utils.hex.fromBytes(encryptedBytes) // 打印或者存储以上加密的分组流之前，需要转换成 16 进制
Log('X', X)

/*
 * 5. X 一分为二，得到：L , R
 */
const halfLength = Math.round(X.length / 2) // X 的一半（四舍五入）
const L_str = X.substr(0, halfLength)
const L = aesjs.utils.utf8.toBytes(L_str)
const R_str = X.substr(halfLength, X.length)
const R = aesjs.utils.utf8.toBytes(R_str)
Log('L_str / R_str', L_str + '/' + R_str)

/*
 * 6. 生成：密钥 K'
 */
const K1_str = randomize('Aa0!', KEY_LENGTH) // ex: => 'LV3u~BSGhw'
Log('K1_str', K1_str)
const K1 = aesjs.utils.utf8.toBytes(K1_str)
Log('K1', K1)

/*
 * 7. 用 stream-cipher 流加密 来解密 L/K1 得到：K
 */
const Seeds = [65, 66, 67, 68, 69] // 'ABCDE' 的16进制列表
const Seeds_hash = sprit.hash(Seeds, KEY_LENGTH)
const K = sprit.decrypt(K1, L)
const K_str = aesjs.utils.utf8.fromBytes(K)
Log('K', K)

/*
 * 8. <X, k>
 */
const XK_list = [X, K_str]
Log('<X, K_str> XK_list', XK_list)
