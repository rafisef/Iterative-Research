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
import { RateLimit } from 'express-rate-limit';
import client from 'prom-client';
import { IpFilter } from 'express-ipfilter';
import { IncomingMessage } from 'http';
import { Server } from 'http';
import {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
} from './routes/fileUpload';
import profileImageFileUpload from './routes/profileImageFileUpload';
import profileImageUrlUpload from './routes/profileImageUrlUpload';
import redirect from './routes/redirect';
import vulnCodeSnippet from './routes/vulnCodeSnippet';
import vulnCodeFixes from './routes/vulnCodeFixes';
import angular from './routes/angular';
import easterEgg from './routes/easterEgg';
import premiumReward from './routes/premiumReward';
import privacyPolicyProof from './routes/privacyPolicyProof';
import appVersion from './routes/appVersion';
import repeatNotification from './routes/repeatNotification';
import continueCode from './routes/continueCode';
import restoreProgress from './routes/restoreProgress';
import fileServer from './routes/fileServer';
import quarantineServer from './routes/quarantineServer';
import keyServer from './routes/keyServer';
import logFileServer from './routes/logfileServer';
import metrics from './routes/metrics';
import authenticatedUsers from './routes/authenticatedUsers';
import currentUser from './routes/currentUser';
import login from './routes/login';
import changePassword from './routes/changePassword';
import resetPassword from './routes/resetPassword';
import securityQuestion from './routes/securityQuestion';
import search from './routes/search';
import coupon from './routes/coupon';
import basket from './routes/basket';
import order from './routes/order';
import verify from './routes/verify';
import recycles from './routes/recycles';
import b2bOrder from './routes/b2bOrder';
import showProductReviews from './routes/showProductReviews';
import createProductReviews from './routes/createProductReviews';
import updateProductReviews from './routes/updateProductReviews';
import likeProductReviews from './routes/likeProductReviews';
import logger from './lib/logger';
import utils from './lib/utils';
import security from './lib/insecurity';
import datacreator from './data/datacreator';
import appConfiguration from './routes/appConfiguration';
import captcha from './routes/captcha';
import trackOrder from './routes/trackOrder';
import countryMapping from './routes/countryMapping';
import basketItems from './routes/basketItems';
import saveLoginIp from './routes/saveLoginIp';
import userProfile from './routes/userProfile';
import updateUserProfile from './routes/updateUserProfile';
import videoHandler from './routes/videoHandler';
import twoFactorAuth from './routes/2fa';
import languageList from './routes/languages';
import config from 'config';
import imageCaptcha from './routes/imageCaptcha';
import dataExport from './routes/dataExport';
import address from './routes/address';
import payment from './routes/payment';
import wallet from './routes/wallet';
import orderHistory from './routes/orderHistory';
import delivery from './routes/delivery';
import deluxe from './routes/deluxe';
import memory from './routes/memory';
import chatbot from './routes/chatbot';
import locales from './data/static/locales.json';
import i18n from 'i18n';

const startTime = Date.now();
const appName = config.get('application.customMetricsPrefix');
const startupGauge = new client.Gauge({
  name: `${appName}_startup_duration_seconds`,
  help: `Duration ${appName} required to perform a certain task during startup`,
  labelNames: ['task']
});

// Wraps the function and measures its (async) execution time
const collectDurationPromise = (name: string, func: Function) => {
  return async (...args: unknown[]) => {
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

const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8')) as Record<string, unknown>;

const app = express();
const server = new Server(app);
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
  securityTxtExpiration.setFullYear(securityTxtExpiration.getFullYear() + 1);
  app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges());
  app.use(['/.well-known/security.txt', '/security.txt'], securityTxt({
    contact: config.get('application.securityTxt.contact'),
    encryption: config.get('application.securityTxt.encryption'),
    acknowledgements: config.get('application.securityTxt.acknowledgements'),
    'Preferred-Languages': [...new Set(locales.map((locale: { key: string }) => locale.key.substr(0, 2)))].join(', '),
    hiring: config.get('application.securityTxt.hiring'),
    expires: securityTxtExpiration.toUTCString()
  }));

  /* robots.txt */
  app.use(robots({ UserAgent: '*', Disallow: '/ftp' }));

  /* Checks for challenges solved by retrieving a file implicitly or explicitly */
  app.use('/assets/public/images/padding', verify.accessControlChallenges());
  app.use('/assets/public/images/products', verify.accessControlChallenges());
  app.use('/assets/public/images/uploads', verify.accessControlChallenges());
  app.use('/assets/i18n', verify.accessControlChallenges());

  /* Checks for challenges solved by abusing SSTi and SSRF bugs */
  app.use('/solve/challenges/server-side', verify.serverSideChallenges());

  /* Create middleware to change paths from the serve-index plugin from absolute to relative */
  const serveIndexMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const orig