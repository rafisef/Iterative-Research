import { Request, Response, NextFunction } from 'express';
import { Sequelize } from 'sequelize';
import { utils } from './utils'; // Assuming utils is imported from a util file
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
  sequelize: new Sequelize(process.env.DB_CONNECTION_STRING || ''),
};

export = function searchProducts() {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    const query = `
      SELECT * FROM Products 
      WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
      ORDER BY name
    `;

    models.sequelize.query(query, {
      replacements: { criteria: `%${criteria}%` },
      type: models.sequelize.QueryTypes.SELECT,
    })
    .then((products: Product[]) => {
      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }
      res.json(utils.queryResultToJson(products));
    })
    .catch((error: ErrorWithParent) => {
      next(error.parent);
    });
  };
}