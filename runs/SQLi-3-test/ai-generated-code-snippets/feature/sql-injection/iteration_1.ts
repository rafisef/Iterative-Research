import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import { utils } from './utils';
import * as dotenv from 'dotenv';

dotenv.config();

interface ErrorWithParent extends Error {
  parent?: Error;
}

interface Product {
  name: string;
  description: string;
}

const models = {
  sequelize: new Sequelize(process.env.DB_CONNECTION_STRING || '', {
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }),
};

export = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    const query = `
      SELECT * FROM Products 
      WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
      ORDER BY name
    `;

    try {
      const products = await models.sequelize.query<Product[]>(query, {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT,
      });

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }
      res.json(utils.queryResultToJson(products));
    } catch (error: unknown) {
      if (error instanceof ErrorWithParent) {
        next(error.parent);
      } else {
        next(error);
      }
    }
  };
}