import { Request, Response, NextFunction } from 'express';
import { QueryTypes } from 'sequelize';
import models from 'path-to-your-models';
import utils from 'path-to-your-utils';

interface Product {
  name: string;
  description: string;
}

export default function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const criteria: string = req.query.q ? String(req.query.q).substring(0, 200) : '';
      const products: Product[] = await models.sequelize.query<Product>(
        `
        SELECT name, description FROM Products
        WHERE (name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL
        ORDER BY name
        `,
        {
          replacements: { criteria: `%${criteria}%` },
          type: QueryTypes.SELECT
        }
      );

      for (const product of products) {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next(error?.parent || error);
    }
  };
}