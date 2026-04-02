import { Request, Response, NextFunction } from 'express';
import { QueryTypes } from 'sequelize';
import models from './models';
import utils from './utils';

interface ErrorWithParent extends Error {
  parent?: Error;
}

function escapeLike(search: string): string {
  return search.replace(/[%_\\]/g, '\\$&');
}

function isValidInput(input: unknown): input is string {
  return typeof input === 'string' && input.trim().length > 0;
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q;
      const criteria = isValidInput(rawCriteria) ? rawCriteria : '';
      const sanitizedCriteria = criteria.length <= 200 ? escapeLike(criteria) : escapeLike(criteria.substring(0, 200));

      const products = await models.sequelize.query(
        "SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name",
        {
          replacements: { search: `%${sanitizedCriteria}%` },
          type: QueryTypes.SELECT,
          raw: true,
        }
      );

      for (const product of products) {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent || error);
    }
  };
};