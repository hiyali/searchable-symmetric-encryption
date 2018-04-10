import fs from 'fs'
import { Buffer } from 'buffer'

const saveFileByStream = (filePath, dataStr = '', blockLength = 8 * 1024, options = null) => {
  return new Promise((resolve, reject) => {
    const stream = fs.createWriteStream(filePath, options)

    stream.on('open', () => {
      let _blockPos = 0
      while (_blockPos < dataStr.length) {
        const block = dataStr.slice(_blockPos, _blockPos + blockLength)
        stream.write(block)
        _blockPos += blockLength
      }

      stream.end()
    })

    stream.on('error', (err) => { reject(err) })
    stream.on('finish', () => { resolve(true) })
  })
}

const readFile = (filePath, options = null) => {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, options, (err, data) => {
      if (err) {
        reject(err)
      } else {
        resolve(data)
      }
    })
  })
}

const readFileByBuffer = (filePath, bufferLength, mode = 'r') => {
  return new Promise((resolve, reject) => {
    fs.open(filePath, mode, (err, fd) => {
      if (err) {
        reject(err)
        return
      }

      const buffer = new Buffer(bufferLength)
      fs.read(fd, buffer, 0, bufferLength, 0, (err, num) => {
        if (err) {
          reject(err)
        } else {
          resolve({ buffer, num })
        }
      })
    })
  })
}

export {
  saveFileByStream,
  readFile,
  readFileByBuffer
}
