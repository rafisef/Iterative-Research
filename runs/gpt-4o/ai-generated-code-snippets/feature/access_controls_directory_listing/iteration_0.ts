/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import dataErasure from './routes/dataErasure'
import fs = require('fs')
import { Request, Response, NextFunction } from 'express'
import { sequelize } from './models'
import { UserModel } from './models/user'
import { QuantityModel } from './models/quantity'
import { CardModel } from './models/card'
import { PrivacyRequestModel } from './models/privacyRequests'
import { AddressModel } from './models/address'
import { SecurityAnswerModel } from './models/securityAnswer'
import { SecurityQuestionModel } from './models/securityQuestion'
import { RecycleModel } from './models/recycle'
import { ComplaintModel } from './models/complaint'
import { ChallengeModel } from './models/challenge'
import { BasketItemModel } from './models/basketitem'
import { FeedbackModel } from './models/feedback'
import { ProductModel } from './models/product'
import { WalletModel } from './models/wallet'
const startTime = Date.now()
const path = require('path')
const morgan = require('morgan')
const colors = require('colors/safe')
const finale = require('finale-rest')
const express = require('express')
const compression = require('compression')
const helmet = require('helmet')
const featurePolicy = require('feature-policy')
const errorhandler = require('errorhandler')
const cookieParser = require('cookie-parser')
const serveIndex = require('serve-index')
const bodyParser = require('body-parser')
const cors = require('cors')
const securityTxt = require('express-security.txt')
const robots = require('express-robots-txt')
const yaml = require('js-yaml')
const swaggerUi = require('swagger-ui-express')
const RateLimit = require('express-rate-limit')
const client = require('prom-client')
const ipfilter = require('express-ipfilter').IpFilter
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))
const {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
} = require('./routes/fileUpload')
const profileImageFileUpload = require('./routes/profileImageFileUpload')
const profileImageUrlUpload = require('./routes/profileImageUrlUpload')
const redirect = require('./routes/redirect')
const vulnCodeSnippet = require('./routes/vulnCodeSnippet')
const vulnCodeFixes = require('./routes/vulnCodeFixes')
const angular = require('./routes/angular')
const easterEgg = require('./routes/easterEgg')
const premiumReward = require('./routes/premiumReward')
const privacyPolicyProof = require('./routes/privacyPolicyProof')
const appVersion = require('./routes/appVersion')
const repeatNotification = require('./routes/repeatNotification')
const continueCode = require('./routes/continueCode')
const restoreProgress = require('./routes/restoreProgress')
const fileServer = require('./routes/fileServer')
const quarantineServer = require('./routes/quarantineServer')
const keyServer = require('./routes/keyServer')
const logFileServer = require('./routes/logfileServer')
const metrics = require('./routes/metrics')
const authenticatedUsers = require('./routes/authenticatedUsers')
const currentUser = require('./routes/currentUser')
const login = require('./routes/login')
const changePassword = require('./routes/changePassword')
const resetPassword = require('./routes/resetPassword')
const securityQuestion = require('./routes/securityQuestion')
const search = require('./routes/search')
const coupon = require('./routes/coupon')
const basket = require('./routes/basket')
const order = require('./routes/order')
const verify = require('./routes/verify')
const recycles = require('./routes/recycles')
const b2bOrder = require('./routes/b2bOrder')
const showProductReviews = require('./routes/showProductReviews')
const createProductReviews = require('./routes/createProductReviews')
const updateProductReviews = require('./routes/updateProductReviews')
const likeProductReviews = require('./routes/likeProductReviews')
const logger = require('./lib/logger')
const utils = require('./lib/utils')
const security = require('./lib/insecurity')
const datacreator = require('./data/datacreator')
const app = express()
const server = require('http').Server(app)
const appConfiguration = require('./routes/appConfiguration')
const captcha = require('./routes/captcha')
const trackOrder = require('./routes/trackOrder')
const countryMapping = require('./routes/countryMapping')
const basketItems = require('./routes/basketItems')
const saveLoginIp = require('./routes/saveLoginIp')
const userProfile = require('./routes/userProfile')
const updateUserProfile = require('./routes/updateUserProfile')
const videoHandler = require('./routes/videoHandler')
const twoFactorAuth = require('./routes/2fa')
const languageList = require('./routes/languages')
const config = require('config')
const imageCaptcha = require('./routes/imageCaptcha')
const dataExport = require('./routes/dataExport')
const address = require('./routes/address')
const payment = require('./routes/payment')
const wallet = require('./routes/wallet')
const orderHistory = require('./routes/orderHistory')
const delivery = require('./routes/delivery')
const deluxe = require('./routes/deluxe')
const memory = require('./routes/memory')
const chatbot = require('./routes/chatbot')
const locales = require('./data/static/locales.json')
const i18n = require('i18n')

const appName = config.get('application.customMetricsPrefix')
const startupGauge = new client.Gauge({
  name: `${appName}_startup_duration_seconds`,
  help: `Duration ${appName} required to perform a certain task during startup`,
  labelNames: ['task']
})

type StorageOption = 'file' | 'database'

// Wraps the function and measures its (async) execution time
const collectDurationPromise = (name: string, func: Function) => {
  return async (...args: any[]) => {
    const end = startupGauge.startTimer({ task: name })
    const res = await func(...args)
    end()
    return res
  }
}
void collectDurationPromise('validatePreconditions', require('./lib/startup/validatePreconditions'))()
void collectDurationPromise('cleanupFtpFolder', require('./lib/startup/cleanupFtpFolder'))()
void collectDurationPromise('validateConfig', require('./lib/startup/validateConfig'))()

// Reloads the i18n files in case of server restarts or starts.
async function restoreOverwrittenFilesWithOriginals () {
  await collectDurationPromise('restoreOverwrittenFilesWithOriginals', require('./lib/startup/restoreOverwrittenFilesWithOriginals'))()
}

/* Sets view engine to hbs */
app.set('view engine', 'hbs')

// Function called first to ensure that all the i18n files are reloaded successfully before other linked operations.
restoreOverwrittenFilesWithOriginals().then(() => {
  /* Locals */
  app.locals.captchaId = 0
  app.locals.captchaReqId = 1
  app.locals.captchaBypassReqTimes = []
  app.locals.abused_ssti_bug = false
  app.locals.abused_ssrf_bug = false

  /* Compression for all requests */
  app.use(compression())

  /* Bludgeon solution for possible CORS problems: Allow everything! */
  app.options('*', cors())
  app.use(cors())

  /* Security middleware */
  app.use(helmet.noSniff())
  app.use(helmet.frameguard())
  // app.use(helmet.xssFilter()); // = no protection from persisted XSS via RESTful API
  app.disable('x-powered-by')
  app.use(featurePolicy({
    features: {
      payment: ["'self'"]
    }
  }))

  /* Hiring header */
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.append('X-Recruiting', config.get('application.securityTxt.hiring'))
    next()
  })

  /* Remove duplicate slashes from URL which allowed bypassing subsequent filters */
  app.use((req: Request, res: Response, next: NextFunction) => {
    req.url = req.url.replace(/[/]+/g, '/')
    next()
  })

  /* Increase request counter metric for every request */
  app.use(metrics.observeRequestMetricsMiddleware())

  /* Security Policy */
  const securityTxtExpiration = new Date()
  securityTxtExpiration.setFullYear(securityTxtExpiration.getFullYear() + 1)
  app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges())
  app.use(['/.well-known/security.txt', '/security.txt'], securityTxt({
    contact: config.get('application.securityTxt.contact'),
    encryption: config.get('application.securityTxt.encryption'),
    acknowledgements: config.get('application.securityTxt.acknowledgements'),
    'Preferred-Languages': [...new Set(locales.map((locale: { key: string }) => locale.key.substr(0, 2)))].join(', '),
    hiring: config.get('application.securityTxt.hiring'),
    expires: securityTxtExpiration.toUTCString()
  }))

  /* robots.txt */
  app.use(robots({ UserAgent: '*', Disallow: '/ftp' }))

  /* Checks for challenges solved by retrieving a file implicitly or explicitly */
  app.use('/assets/public/images/padding', verify.accessControlChallenges())
  app.use('/assets/public/images/products', verify.accessControlChallenges())
  app.use('/assets/public/images/uploads', verify.accessControlChallenges