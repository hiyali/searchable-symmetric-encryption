import logger from 'node-color-log'

export default function (title = '', message = '', setting = {}) {
  logger.color(setting.titleColor || 'green').log(title)
  logger.color(setting.messageColor || 'yellow').log(message)
}
