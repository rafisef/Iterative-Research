import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';

interface Product {
  name: string;
  description: string;
  [key: string]: any;
}

interface ErrorWithParent extends Error {
  parent: Error;
}

const models = {
  sequelize: new Sequelize('database', 'username', 'password', {
    dialect: 'mysql',
  }),
};

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string ?? '');
      criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

      const query = `
        SELECT * FROM Products 
        WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
        ORDER BY name
      `;
      const products: Product[] = await models.sequelize.query(query, {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT,
      });

      products.forEach(product => {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      });

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent);
    }
  };
};