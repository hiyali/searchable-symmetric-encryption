import aesjs from 'aes-js'
import spritzjs from 'spritzjs'
import randomize from 'randomatic'
import { argv } from 'yargs'

import Log from './log.js'
import { HEX_ARR_XOR } from './utils.js'
import { KEY_LENGTH, BUFFER_LENGTH, KB } from './constants.js'
import { saveFileByStream, readFile, readFileByBuffer } from './file.js'

(async () => {
  const sprit = spritzjs()
  Log('Keep working ...', '', {
    titleColor: 'cyan'
  })

  /*
   * 1. 生成：密钥 K"
   */
  const K2_str = randomize('Aa0!', KEY_LENGTH) // ex: => 'LV3u~BSGhw'
  Log('K2_str', K2_str)
  const K2 = aesjs.utils.utf8.toBytes(K2_str)
  Log('K2', K2)

  /*
   * 2. 生成：分组加密所需的向量 IV (initialization vector)
   * 解释：
   * 需协商一个初始化向量（IV），这个IV没有实际意义，只是在第一次计算的时候需要用到而已。
   * 采用这种模式的话安全性会有所提高。
   */
  const IV_str = randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
  const IV = aesjs.utils.utf8.toBytes(IV_str)

  /*
   * 3. 接收输入的文字或生成：纯字符串 Wi
   */
  let inputText = argv.text // 输入的文字
  Log('inputText', inputText)
  if (typeof inputText === 'string') {
    inputText = inputText.substr(0, KEY_LENGTH) // 截取输入的文字的 前 16 位
    inputText = inputText.padEnd(KEY_LENGTH, '0') // 用字符0填充不到 16 位的字符串
  }
  const Wi_str = inputText || randomize('Aa0!', KEY_LENGTH) // must be 16 Bytes
  Log('Wi_str', Wi_str)
  const Wi = aesjs.utils.utf8.toBytes(Wi_str)
  Log('Wi', Wi)

  /*
   * 4. CBC - Cipher-Block Chaining 分组密码 （同：块加密）
   */
  const aesCbc = new aesjs.ModeOfOperation.cbc(K2, IV)
  const encryptedBytes = aesCbc.encrypt(Wi)
  const X = aesjs.utils.hex.fromBytes(encryptedBytes) // 打印或者存储以上加密的分组流之前，需要转换成 16 进制
  Log('X', X)

  /*
   * 5. X 一分为二，得到：Li , Ri
   */
  const halfLength = Math.round(X.length / 2) // X 的一半（四舍五入）
  const Li_str = X.substr(0, halfLength)
  const Li = aesjs.utils.utf8.toBytes(Li_str)
  const Ri_str = X.substr(halfLength, X.length)
  const Ri = aesjs.utils.utf8.toBytes(Ri_str)
  Log('Li_str / Ri_str', Li_str + '/' + Ri_str)
  Log('Li', Li)
  Log('Ri', Ri)

  /*
   * 【存储】X (encryptedHex)
   */
  const time = 'const' || (new Date()).getTime()
  const filePath = `dist/encryptedHex_${time}.txt`

  try {
    await saveFileByStream(filePath, X, BUFFER_LENGTH, { encoding: 'utf8' })
  } catch (err) {
    Log('Something went wrong (saveFileByStream):', err, {
      titleColor: 'red'
    })
  }

  /*
   * 6. 生成：密钥 K'
   */
  const K1_str = randomize('Aa0!', KEY_LENGTH) // ex: => 'LV3u~BSGhw'
  Log('K1_str', K1_str)
  const K1 = aesjs.utils.utf8.toBytes(K1_str)
  Log('K1', K1)

  /*
   * 7. 用 stream-cipher & hash 函数生成：Si
   */
  const M = [65, 66, 67, 68, 69] // 模：ABCDE 的charCode
  const Si = sprit.hash(M, KEY_LENGTH) // => 16 位哈希
  Log('Si', Si)

  /*
   * 8. 用 stream-cipher 流加密 来解密 Li 得到：Ki
   */
  const Ki = sprit.decrypt(K1, Li)
  Log('Ki', Ki)

  /*
   * 9. 用 stream-cipher 流加密/Ki 来加密 Si：FKi(Si)
   */
  const FKiSi = sprit.encrypt(Ki, Si)
  Log('FKiSi', FKiSi)

  /*
   * 10. 模2加法（异或运算）Ri 与 FKiSi 得到：Ci
   */
  const Ci = HEX_ARR_XOR(Ri, FKiSi)
  Log('Ci', Ci)
})()
