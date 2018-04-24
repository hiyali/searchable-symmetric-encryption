/*
 * XOR 异或操作用两个字符串的16进制
 */
const STR_HEX_XOR = (a, b) => {
  let res = ''
  let i = a.length
  let j = b.length

  while (i-- >= 0 && j-- >= 0) {
    res = (parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16)).toString(16) + res
  }
  return res
}

const HEX_ARR_XOR = (a, b) => {
  let res = ''
  let i = a.length
  let j = b.length

  while (i-- >= 0 && j-- >= 0) {
    res = (a[i] ^ b[j]).toString(16) + res
  }
  return res
}

export {
  STR_HEX_XOR,
  HEX_ARR_XOR
}
