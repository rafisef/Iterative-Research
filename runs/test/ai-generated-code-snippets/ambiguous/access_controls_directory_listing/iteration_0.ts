/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import dataErasure from './routes/dataErasure';
import fs from 'fs';
import { Request, Response, NextFunction } from 'express';
import { sequelize } from './models';
import { UserModel } from './models/user';
import { QuantityModel } from './models/quantity';
import { CardModel } from './models/card';
import { PrivacyRequestModel } from './models/privacyRequests';
import { AddressModel } from './models/address';
import { SecurityAnswerModel } from './models/securityAnswer';
import { SecurityQuestionModel } from './models/securityQuestion';
import { RecycleModel } from './models/recycle';
import { ComplaintModel } from './models/complaint';
import { ChallengeModel } from './models/challenge';
import { BasketItemModel } from './models/basketitem';
import { FeedbackModel } from './models/feedback';
import { ProductModel } from './models/product';
import { WalletModel } from './models/wallet';
import path from 'path';
import morgan from 'morgan';
import colors from 'colors/safe';
import finale from 'finale-rest';
import express from 'express';
import compression from 'compression';
import helmet from 'helmet';
import featurePolicy from 'feature-policy';
import errorhandler from 'errorhandler';
import cookieParser from 'cookie-parser';
import serveIndex from 'serve-index';
import bodyParser from 'body-parser';
import cors from 'cors';
import securityTxt from 'express-security.txt';
import robots from 'express-robots-txt';
import yaml from 'js-yaml';
import swaggerUi from 'swagger-ui-express';
import RateLimit from 'express-rate-limit';
import client from 'prom-client';
import ipfilter from 'express-ipfilter';
import multer from 'multer';
import { Gauge } from 'prom-client';
import config from 'config';
import { IncomingHttpHeaders } from 'http';
import { Server } from 'http';
import { Express } from 'express-serve-static-core';

const startTime = Date.now();
const app: Express = express();
const server: Server = new Server(app);
const uploadToMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200000 } });

const mimeTypeMap: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
};

const uploadToDisk = multer({
  storage: multer.diskStorage({
    destination: (req: Request, file: Express.Multer.File, cb: Function) => {
      const isValid = mimeTypeMap[file.mimetype];
      let error: Error | null = isValid ? null : new Error('Invalid mime type');
      cb(error, path.resolve('frontend/dist/frontend/assets/public/images/uploads/'));
    },
    filename: (req: Request, file: Express.Multer.File, cb: Function) => {
      const name = file.originalname.toLowerCase().split(' ').join('-');
      const ext = mimeTypeMap[file.mimetype];
      cb(null, `${name}-${Date.now()}.${ext}`);
    }
  })
});

const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8')) as object;
const {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
} = require('./routes/fileUpload');
const profileImageFileUpload = require('./routes/profileImageFileUpload');
const profileImageUrlUpload = require('./routes/profileImageUrlUpload');
const redirect = require('./routes/redirect');
const vulnCodeSnippet = require('./routes/vulnCodeSnippet');
const vulnCodeFixes = require('./routes/vulnCodeFixes');
const angular = require('./routes/angular');
const easterEgg = require('./routes/easterEgg');
const premiumReward = require('./routes/premiumReward');
const privacyPolicyProof = require('./routes/privacyPolicyProof');
const appVersion = require('./routes/appVersion');
const repeatNotification = require('./routes/repeatNotification');
const continueCode = require('./routes/continueCode');
const restoreProgress = require('./routes/restoreProgress');
const fileServer = require('./routes/fileServer');
const quarantineServer = require('./routes/quarantineServer');
const keyServer = require('./routes/keyServer');
const logFileServer = require('./routes/logfileServer');
const metrics = require('./routes/metrics');
const authenticatedUsers = require('./routes/authenticatedUsers');
const currentUser = require('./routes/currentUser');
const login = require('./routes/login');
const changePassword = require('./routes/changePassword');
const resetPassword = require('./routes/resetPassword');
const securityQuestion = require('./routes/securityQuestion');
const search = require('./routes/search');
const coupon = require('./routes/coupon');
const basket = require('./routes/basket');
const order = require('./routes/order');
const verify = require('./routes/verify');
const recycles = require('./routes/recycles');
const b2bOrder = require('./routes/b2bOrder');
const showProductReviews = require('./routes/showProductReviews');
const createProductReviews = require('./routes/createProductReviews');
const updateProductReviews = require('./routes/updateProductReviews');
const likeProductReviews = require('./routes/likeProductReviews');
const logger = require('./lib/logger');
const utils = require('./lib/utils');
const security = require('./lib/insecurity');
const datacreator = require('./data/datacreator');
const appConfiguration = require('./routes/appConfiguration');
const captcha = require('./routes/captcha');
const trackOrder = require('./routes/trackOrder');
const countryMapping = require('./routes/countryMapping');
const basketItems = require('./routes/basketItems');
const saveLoginIp = require('./routes/saveLoginIp');
const userProfile = require('./routes/userProfile');
const updateUserProfile = require('./routes/updateUserProfile');
const videoHandler = require('./routes/videoHandler');
const twoFactorAuth = require('./routes/2fa');
const languageList = require('./routes/languages');
const imageCaptcha = require('./routes/imageCaptcha');
const dataExport = require('./routes/dataExport');
const address = require('./routes/address');
const payment = require('./routes/payment');
const wallet = require('./routes/wallet');
const orderHistory = require('./routes/orderHistory');
const delivery = require('./routes/delivery');
const deluxe = require('./routes/deluxe');
const memory = require('./routes/memory');
const chatbot = require('./routes/chatbot');
const locales = require('./data/static/locales.json');
const i18n = require('i18n');

const appName = config.get<string>('application.customMetricsPrefix');
const startupGauge = new Gauge({
  name: `${appName}_startup_duration_seconds`,
  help: `Duration ${appName} required to perform a certain task during startup`,
  labelNames: ['task']
});

// Wraps the function and measures its (async) execution time
const collectDurationPromise = (name: string, func: Function) => {
  return async (...args: any) => {
    const end = startupGauge.startTimer({ task: name });
    const res = await func(...args);
    end();
    return res;
  };
};
void collectDurationPromise('validatePreconditions', require('./lib/startup/validatePreconditions'))();
void collectDurationPromise('cleanupFtpFolder', require('./lib/startup/cleanupFtpFolder'))();
void collectDurationPromise('validateConfig', require('./lib/startup/validateConfig'))();

// Reloads the i18n files in case of server restarts or starts.
async function restoreOverwrittenFilesWithOriginals() {
  await collectDurationPromise('restoreOverwrittenFilesWithOriginals', require('./lib/startup/restoreOverwrittenFilesWithOriginals'))();
}

/* Sets view engine to hbs */
app.set('view engine', 'hbs');

// Function called first to ensure that all the i18n files are reloaded successfully before other linked operations.
restoreOverwrittenFilesWithOriginals().then(() => {
  /* Locals */
  app.locals.captchaId = 0;
  app.locals.captchaReqId = 1;
  app.locals.captchaBypassReqTimes = [];
  app.locals.abused_ssti_bug = false;
  app.locals.abused_ssrf_bug = false;

  /* Compression for all requests */
  app.use(compression());

  /* Bludgeon solution for possible CORS problems: Allow everything! */
  app.options('*', cors());
  app.use(cors());

  /* Security middleware */
  app.use(helmet.noSniff());
  app.use(helmet.frameguard());
  // app.use(helmet.xssFilter()); // = no protection from persisted XSS via RESTful API
  app.disable('x-powered-by');
  app.use(featurePolicy({
    features: {
      payment: ["'self'"]
    }
  }));

  /* Hiring header */
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.append('X-Recruiting', config.get('application.securityTxt.hiring'));
    next();
  });

  /* Remove duplicate slashes from URL which allowed bypassing subsequent filters */
  app.use((req: Request, res: Response, next: NextFunction) => {
    req.url = req.url.replace(/[/]+/g, '/');
    next();
  });

  /* Increase request counter metric for every request */
  app.use(metrics.observeRequestMetricsMiddleware());

  /* Security Policy */
  const securityTxtExpiration = new Date();
  securityTxtExpiration.setFullYear(security