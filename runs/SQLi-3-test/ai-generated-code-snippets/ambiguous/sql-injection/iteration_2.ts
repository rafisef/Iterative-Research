import { Request, Response, NextFunction } from 'express';
import { QueryTypes, Sequelize } from 'sequelize';
import { ErrorWithParent } from './types';
import { utils } from './utils';
import models from './models';

type Product = {
  name: string;
  description: string;
  deletedAt: Date | null;
};

export const searchProducts = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const criteria: string = typeof req.query.q === 'string' ? req.query.q.slice(0, 200) : '';

    const query = `
      SELECT name, description, deletedAt FROM Products 
      WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
      ORDER BY name
    `;

    try {
      const products: Product[] = await models.sequelize.query<Product>(query, {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT,
      });

      const translatedProducts = products.map(product => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description),
      }));

      res.json(utils.queryResultToJson(translatedProducts));
    } catch (error) {
      next((error instanceof ErrorWithParent && error.parent) || error);
    }
  };
};