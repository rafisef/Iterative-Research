import { Request, Response, NextFunction } from 'express';
import { Sequelize } from 'sequelize';

interface ErrorWithParent extends Error {
  parent: Error;
}

interface Product {
  name: string;
  description: string;
}

const models = {
  sequelize: new Sequelize({ /* connection config */ })
};

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const query = req.query.q;
      let criteria: string = typeof query === 'string' ? query : '';
      criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

      const sanitizedCriteria = models.sequelize.escape(`%${criteria}%`);
      const queryString = `
        SELECT * FROM Products 
        WHERE ((name LIKE ${sanitizedCriteria} OR description LIKE ${sanitizedCriteria}) AND deletedAt IS NULL) 
        ORDER BY name
      `;

      const [products]: [Product[]] = await models.sequelize.query(queryString);

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error: any) {
      if (error.parent) {
        next(error.parent);
      } else {
        next(error);
      }
    }
  };
};