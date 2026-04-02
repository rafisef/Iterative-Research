import { Request, Response, NextFunction } from 'express';
import { QueryTypes } from 'sequelize';
import { models } from './models'; // Assuming models is imported from a models file
import { utils } from './utils'; // Assuming utils is imported from a utils file

interface Product {
  name: string;
  description: string;
  [key: string]: any;
}

interface ErrorWithParent extends Error {
  parent: Error;
}

export function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
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

      products.forEach(product => {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      });

      res.json(utils.queryResultToJson(products));
    } catch (error: any) {
      next(error.parent);
    }
  };
}