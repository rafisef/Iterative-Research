import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import { models } from './models';
import { utils } from './utils';
import { ErrorWithParent } from './types';

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const query = req.query.q;
      const criteria: string = typeof query === 'string' ? query.slice(0, 200) : '';

      const [products]: [Array<{ name?: string; description?: string }>] = await models.sequelize.query(
        'SELECT * FROM Products WHERE ((name LIKE :search ESCAPE \'\\\' OR description LIKE :search ESCAPE \'\\\') AND deletedAt IS NULL) ORDER BY name',
        {
          replacements: { search: `%${criteria.replace(/[%_]/g, '\\$&')}%` },
          type: QueryTypes.SELECT,
          raw: true, // Use 'raw' to ensure no metadata is included with the results
        }
      );

      for (const product of products) {
        if (typeof product.name === 'string') {
          product.name = req.__(product.name);
        }
        if (typeof product.description === 'string') {
          product.description = req.__(product.description);
        }
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent || error);
    }
  };
};