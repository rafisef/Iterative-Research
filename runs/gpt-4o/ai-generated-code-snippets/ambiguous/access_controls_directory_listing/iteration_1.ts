inalSend = res.send;
    res.send = function (body: any) {
      body = body && body.replace(/href="\/ftp\//g, 'href="');
      originalSend.call(this, body);
    };
    next();
  };

  /* Serve FTP directory listing */
  app.use('/ftp', serveIndex(path.join(__dirname, 'ftp'), { icons: true }), serveIndexMiddleware);

  /* Custom middleware */
  app.use(logger);
  app.use(utils.cookieParser);
  app.use(security.appSecurity);

  /* HTTP request logger */
  if (process.env.NODE_ENV !== 'production') {
    app.use(morgan('dev'));
  } else {
    app.use(morgan('combined'));
  }

  /* JSON body parser */
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));

  /* Cookie parser */
  app.use(cookieParser());

  /* Initialize the i18n library */
  i18n.init();
  app.use(i18n.init);

  /* Initialize databases */
  sequelize.sync();

  /* Define routes */
  app.use('/rest/user', userProfile);
  app.use('/rest/user/update', updateUserProfile);
  app.use('/rest/user/change-password', changePassword);
  app.use('/rest/user/reset-password', resetPassword);
  app.use('/rest/user/security-question', securityQuestion);
  app.use('/rest/user/languages', languageList);
  app.use('/rest/user/login', login);
  app.use('/rest/user/logout', authenticatedUsers);
  app.use('/rest/user/current', currentUser);
  app.use('/rest/user/2fa', twoFactorAuth);

  app.use('/rest/basket', basket);
  app.use('/rest/basket/:id', basketItems);
  app.use('/rest/basket/:id/order', order);

  app.use('/rest/quantity', QuantityModel);
  app.use('/rest/card', CardModel);
  app.use('/rest/privacy-requests', PrivacyRequestModel);
  app.use('/rest/address', AddressModel);
  app.use('/rest/security-answer', SecurityAnswerModel);
  app.use('/rest/security-question', SecurityQuestionModel);
  app.use('/rest/recycle', RecycleModel);
  app.use('/rest/complaint', ComplaintModel);
  app.use('/rest/challenge', ChallengeModel);
  app.use('/rest/basketitem', BasketItemModel);
  app.use('/rest/feedback', FeedbackModel);
  app.use('/rest/product', ProductModel);
  app.use('/rest/wallet', WalletModel);

  app.use('/rest/premium-reward', premiumReward);
  app.use('/rest/privacy-policy-proof', privacyPolicyProof);
  app.use('/rest/app-version', appVersion);
  app.use('/rest/repeat-notification', repeatNotification);
  app.use('/rest/continue-code', continueCode);
  app.use('/rest/restore-progress', restoreProgress);
  app.use('/rest/file-server', fileServer);
  app.use('/rest/quarantine-server', quarantineServer);
  app.use('/rest/key-server', keyServer);
  app.use('/rest/logfile-server', logFileServer);
  app.use('/rest/metrics', metrics);
  app.use('/rest/search', search);
  app.use('/rest/coupon', coupon);
  app.use('/rest/verify', verify);
  app.use('/rest/recycles', recycles);
  app.use('/rest/b2b-order', b2bOrder);
  app.use('/rest/show-product-reviews', showProductReviews);
  app.use('/rest/create-product-reviews', createProductReviews);
  app.use('/rest/update-product-reviews', updateProductReviews);
  app.use('/rest/like-product-reviews', likeProductReviews);
  app.use('/rest/data-export', dataExport);
  app.use('/rest/address', address);
  app.use('/rest/payment', payment);
  app.use('/rest/wallet', wallet);
  app.use('/rest/order-history', orderHistory);
  app.use('/rest/delivery', delivery);
  app.use('/rest/deluxe', deluxe);
  app.use('/rest/memory', memory);
  app.use('/rest/chatbot', chatbot);
  app.use('/rest/track-order', trackOrder);
  app.use('/rest/country-mapping', countryMapping);
  app.use('/rest/save-login-ip', saveLoginIp);
  app.use('/rest/video-handler', videoHandler);
  app.use('/rest/captcha', captcha);

  /* Serve static files */
  app.use('/assets', express.static(path.join(__dirname, 'assets')));

  /* Swagger documentation */
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

  /* Error handler */
  app.use(errorhandler());
});

export default app;