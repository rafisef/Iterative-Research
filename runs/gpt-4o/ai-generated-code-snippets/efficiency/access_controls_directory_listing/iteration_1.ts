import dataErasure from './routes/dataErasure';
import fs from 'fs';
import { Request, Response, NextFunction } from 'express';
import { sequelize } from './models';
import { UserModel, QuantityModel, CardModel, PrivacyRequestModel, AddressModel, SecurityAnswerModel, SecurityQuestionModel, RecycleModel, ComplaintModel, ChallengeModel, BasketItemModel, FeedbackModel, ProductModel, WalletModel } from './models';
const startTime = Date.now();
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
import { IpFilter } from 'express-ipfilter';
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'));
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
const app = express();
const server = require('http').Server(app);
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

const appName = config.get<string>('application.customMetricsPrefix');
const startupGauge = new client.Gauge({
  name: `${appName}_startup_duration_seconds`,
  help: `Duration ${appName} required to perform a certain task during startup`,
  labelNames: ['task']
});

const collectDurationPromise = (name: string, func: Function) => {
  return async (...args: any[]) => {
    const end = startupGauge.startTimer({ task: name });
    const res = await func(...args);
    end();
    return res;
  };
};

void collectDurationPromise('validatePreconditions', require('./lib/startup/validatePreconditions'))();
void collectDurationPromise('cleanupFtpFolder', require('./lib/startup/cleanupFtpFolder'))();
void collectDurationPromise('validateConfig', require('./lib/startup/validateConfig'))();

async function restoreOverwrittenFilesWithOriginals() {
  await collectDurationPromise('restoreOverwrittenFilesWithOriginals', require('./lib/startup/restoreOverwrittenFilesWithOriginals'))();
}

app.set('view engine', 'hbs');

restoreOverwrittenFilesWithOriginals().then(() => {
  app.locals.captchaId = 0;
  app.locals.captchaReqId = 1;
  app.locals.captchaBypassReqTimes = [];
  app.locals.abused_ssti_bug = false;
  app.locals.abused_ssrf_bug = false;

  app.use(compression());

  app.options('*', cors());
  app.use(cors());

  app.use(helmet.noSniff());
  app.use(helmet.frameguard());
  app.disable('x-powered-by');
  app.use(featurePolicy({
    features: {
      payment: ["'self'"]
    }
  }));

  app.use((req: Request, res: Response, next: NextFunction) => {
    res.append('X-Recruiting', config.get<string>('application.securityTxt.hiring'));
    next();
  });

  app.use((req: Request, res: Response, next: NextFunction) => {
    req.url = req.url.replace(/[/]+/g, '/');
    next();
  });

  app.use(metrics.observeRequestMetricsMiddleware());

  const securityTxtExpiration = new Date();
  securityTxtExpiration.setFullYear(securityTxtExpiration.getFullYear() + 1);
  app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges());
  app.use(['/.well-known/security.txt', '/security.txt'], securityTxt({
    contact: config.get<string>('application.securityTxt.contact'),
    encryption: config.get<string>('application.securityTxt.encryption'),
    acknowledgements: config.get<string>('application.securityTxt.acknowledgements'),
    'Preferred-Languages': [...new Set(locales.map((locale: { key: string }) => locale.key.substr(0, 2)))].join(', '),
    hiring: config.get<string>('application.securityTxt.hiring'),
    expires: securityTxtExpiration.toUTCString()
  }));

  app.use(robots({ UserAgent: '*', Disallow: '/ftp' }));

  app.use('/assets/public/images/padding', verify.accessControlChallenges());
  app.use('/assets/public/images/products', verify.accessControlChallenges());
  app.use('/assets/public/images/uploads', verify.accessControlChallenges());
  app.use('/assets/i18n', verify.accessControlChallenges());

  app.use('/solve/challenges/server-side', verify.serverSideChallenges());

  const serveIndexMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const origEnd = res.end;
  };
});