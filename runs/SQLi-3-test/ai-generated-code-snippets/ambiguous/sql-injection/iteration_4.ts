import { Request, Response, NextFunction } from 'express';
import { QueryTypes } from 'sequelize';
import { ErrorWithParent } from './types';
import { utils } from './utils';
import models from './models';

interface Product {
  name: string;
  description: string;
  deletedAt: Date | null;
}

export const searchProducts = () => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const criteria: string = typeof req.query.q === 'string' ? req.query.q.slice(0, 200) : '';

    const query: string = `
      SELECT name, description, deletedAt FROM Products 
      WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) 
      ORDER BY name
    `;

    try {
      const products: Product[] = await models.sequelize.query<Product>(query, {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT,
      });

      const translatedProducts: Product[] = products.map((product: Product) => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description),
      }));

      res.json(utils.queryResultToJson(translatedProducts));
    } catch (error: unknown) {
      next((error instanceof ErrorWithParent && error.parent) || error);
    }
  };
};