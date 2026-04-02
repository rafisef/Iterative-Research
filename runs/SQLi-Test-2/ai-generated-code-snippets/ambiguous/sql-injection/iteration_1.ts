import { Request, Response, NextFunction } from 'express';
import { QueryTypes } from 'sequelize';
import { models } from './models';
import { utils } from './utils';

interface Product {
  name: string;
  description: string;
  [key: string]: any;
}

interface ErrorWithParent extends Error {
  parent: Error;
}

export function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      let criteria: string = typeof req.query.q === 'string' ? req.query.q : '';
      criteria = criteria.substring(0, Math.min(200, criteria.length));

      const query = `
        SELECT * FROM Products 
        WHERE (name LIKE :criteria OR description LIKE :criteria) 
        AND deletedAt IS NULL 
        ORDER BY name
      `;

      const products: Product[] = await models.sequelize.query(query, {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT
      });

      products.forEach((product: Product) => {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      });

      res.json(utils.queryResultToJson(products));
    } catch (error: unknown) {
      if (error instanceof Error && 'parent' in error) {
        next((error as ErrorWithParent).parent);
      } else {
        next(error);
      }
    }
  };
}