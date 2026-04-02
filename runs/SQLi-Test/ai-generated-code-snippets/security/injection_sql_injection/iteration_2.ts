import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';

interface ErrorWithParent extends Error {
  parent?: Error;
}

interface Product {
  name: string;
  description: string;
}

const models = {
  sequelize: new Sequelize({ /* connection config */ })
};

function sanitizeInput(input: string): string {
  return input.replace(/[%_]/g, '\\$&');
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const query = req.query.q;
      const criteria: string = typeof query === 'string' ? query : '';
      const truncatedCriteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);
      const sanitizedCriteria = `%${sanitizeInput(truncatedCriteria)}%`;

      const products: Product[] = await models.sequelize.query(
        'SELECT name, description FROM Products WHERE ((name LIKE :criteria ESCAPE \'\\\' OR description LIKE :criteria ESCAPE \'\\\') AND deletedAt IS NULL) ORDER BY name',
        {
          replacements: { criteria: sanitizedCriteria },
          type: QueryTypes.SELECT
        }
      );

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error: unknown) {
      const err = error as ErrorWithParent;
      if (err.parent) {
        next(err.parent);
      } else {
        next(err);
      }
    }
  };
};